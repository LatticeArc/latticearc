//! Key Format Stability Tests
//!
//! Ensures that key construction and representation APIs remain stable.

#[cfg(test)]
mod tests {
    use arc_primitives::kem::ml_kem::{
        MlKem, MlKemCiphertext, MlKemError, MlKemPublicKey, MlKemSecurityLevel,
    };
    use rand::rngs::OsRng;

    // ========================================================================
    // Public API Surface Tests
    // ========================================================================

    #[test]
    fn api_stability_public_key_has_to_bytes() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");

        // Verify to_bytes() exists and returns Vec<u8>
        let _bytes: Vec<u8> = pk.to_bytes();
    }

    #[test]
    fn api_stability_public_key_from_bytes_exists() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");

        let bytes = pk.to_bytes();

        // Verify from_bytes() exists and works
        let _restored: MlKemPublicKey =
            MlKemPublicKey::from_bytes(&bytes, MlKemSecurityLevel::MlKem512)
                .expect("from_bytes should exist and work");
    }

    #[test]
    fn api_stability_ciphertext_into_bytes() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");
        let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

        // Verify into_bytes() exists (MlKemCiphertext uses consuming conversion)
        let _bytes: Vec<u8> = ct.into_bytes();
    }

    #[test]
    fn api_stability_ciphertext_as_bytes() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");
        let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

        // Verify as_bytes() exists for borrowing
        let _bytes: &[u8] = ct.as_bytes();
    }

    #[test]
    fn api_stability_shared_secret_as_bytes() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");
        let (ss, _ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

        // Verify as_bytes() exists and returns &[u8]
        let _bytes: &[u8] = ss.as_bytes();
    }

    // ========================================================================
    // Constructor API Tests
    // ========================================================================

    #[test]
    fn api_stability_ciphertext_new_exists() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");
        let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

        let bytes = ct.into_bytes();

        // Verify MlKemCiphertext::new() exists
        let _restored =
            MlKemCiphertext::new(MlKemSecurityLevel::MlKem512, bytes).expect("new should work");
    }

    // ========================================================================
    // Security Level Enum Stability
    // ========================================================================

    #[test]
    fn api_stability_security_levels_exist() {
        // Verify all expected security levels exist
        let _level_512 = MlKemSecurityLevel::MlKem512;
        let _level_768 = MlKemSecurityLevel::MlKem768;
        let _level_1024 = MlKemSecurityLevel::MlKem1024;
    }

    #[test]
    fn api_stability_security_level_is_copy() {
        let level = MlKemSecurityLevel::MlKem768;
        let level_copy = level; // Should work because Copy is implemented
        assert!(matches!(level_copy, MlKemSecurityLevel::MlKem768));
    }

    // ========================================================================
    // Generate/Encapsulate/Decapsulate API Stability
    // ========================================================================

    #[test]
    fn api_stability_generate_keypair_signature() {
        let mut rng = OsRng;

        // Verify generate_keypair takes (rng, level) and returns Result<(PK, SK), Error>
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512);
        assert!(result.is_ok());
    }

    #[test]
    fn api_stability_encapsulate_signature() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");

        // Verify encapsulate takes (rng, pk) and returns Result<(SS, CT), Error>
        let result = MlKem::encapsulate(&mut rng, &pk);
        assert!(result.is_ok());
    }

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization for decapsulation"]
    fn api_stability_decapsulate_signature() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");
        let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

        // Verify decapsulate takes (sk, ct) and returns Result<SS, Error>
        let result = MlKem::decapsulate(&sk, &ct);
        assert!(result.is_ok());
    }

    // ========================================================================
    // Error Type Stability
    // ========================================================================

    #[test]
    fn api_stability_error_types_exist() {
        // Verify error variants exist by constructing them
        let _invalid_key = MlKemError::InvalidKeyLength {
            variant: "512".to_string(),
            key_type: "public".to_string(),
            size: 800,
            actual: 0,
        };

        let _invalid_ct = MlKemError::InvalidCiphertextLength {
            variant: "512".to_string(),
            expected: 768,
            actual: 0,
        };
    }
}
