#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ECDH P-256 key exchange
//!
//! Tests that P-256 ECDH operations handle arbitrary input data
//! without crashing and produce valid shared secrets.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ecdh::EcdhP256KeyPair;

fuzz_target!(|data: &[u8]| {
    // Test 1: Generate keypairs and perform key agreement
    if let (Ok(alice), Ok(bob)) = (EcdhP256KeyPair::generate(), EcdhP256KeyPair::generate()) {
        // Clone public keys before consuming keypairs
        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        // Verify public key sizes (65 bytes for uncompressed P-256)
        assert_eq!(alice_pk.len(), 65, "P-256 public key must be 65 bytes (uncompressed)");
        assert_eq!(bob_pk.len(), 65, "P-256 public key must be 65 bytes (uncompressed)");

        // Perform key agreement (consume keys)
        let alice_secret = alice.agree(&bob_pk);
        let bob_secret = bob.agree(&alice_pk);

        if let (Ok(as_val), Ok(bs_val)) = (alice_secret, bob_secret) {
            // Shared secrets must match
            assert_eq!(
                as_val, bs_val,
                "Shared secrets must match for valid key exchange"
            );

            // Shared secret must be 32 bytes (x-coordinate)
            assert_eq!(as_val.len(), 32, "P-256 shared secret must be 32 bytes");
        }
    }

    // Test 2: Key agreement with fuzzed public key
    if data.len() >= 65 {
        if let Ok(keypair) = EcdhP256KeyPair::generate() {
            let fuzzed_pk = &data[..65];

            // Attempt agreement with fuzzed public key
            let result = keypair.agree(fuzzed_pk);
            // Will likely fail (point not on curve) but should not crash
            let _ = result;
        }
    }

    // Test 3: Key agreement with invalid public key size
    if let Ok(keypair) = EcdhP256KeyPair::generate() {
        // Too short
        let short_pk = &data[..32.min(data.len())];
        let result = keypair.agree(short_pk);
        assert!(result.is_err(), "Invalid public key size should fail");
    }

    // Test 4: Key agreement with too long public key
    if data.len() >= 100 {
        if let Ok(keypair) = EcdhP256KeyPair::generate() {
            let long_pk = &data[..100];
            let result = keypair.agree(long_pk);
            assert!(result.is_err(), "Invalid public key size should fail");
        }
    }

    // Test 5: Multiple key generations should produce different keys
    if let (Ok(kp1), Ok(kp2)) = (EcdhP256KeyPair::generate(), EcdhP256KeyPair::generate()) {
        assert_ne!(
            kp1.public_key_bytes(),
            kp2.public_key_bytes(),
            "Different key generations should produce different keys"
        );
    }

    // Test 6: Public key format validation (must start with 0x04 for uncompressed)
    if let Ok(keypair) = EcdhP256KeyPair::generate() {
        let pk = keypair.public_key_bytes();
        assert_eq!(
            pk[0], 0x04,
            "Uncompressed P-256 public key must start with 0x04"
        );
    }

    // Test 7: Key agreement with point at infinity (invalid)
    if let Ok(keypair) = EcdhP256KeyPair::generate() {
        // Construct invalid point
        let mut invalid_pk = [0u8; 65];
        invalid_pk[0] = 0x04; // Uncompressed format
        // Rest is zeros - not a valid point
        let result = keypair.agree(&invalid_pk);
        assert!(result.is_err(), "Point at infinity should be rejected");
    }

    // Test 8: Key agreement with malformed uncompressed point
    if data.len() >= 65 {
        if let Ok(keypair) = EcdhP256KeyPair::generate() {
            // Wrong format byte
            let mut malformed = [0u8; 65];
            malformed[0] = 0x02; // Compressed format byte
            for (i, b) in data[1..65.min(data.len())].iter().enumerate() {
                malformed[i + 1] = *b;
            }
            let result = keypair.agree(&malformed);
            // May fail due to format or point validation
            let _ = result;
        }
    }
});
