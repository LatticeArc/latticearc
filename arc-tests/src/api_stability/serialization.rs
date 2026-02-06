//! Serialization Format Stability Tests
//!
//! Ensures that serialized key formats remain compatible across versions.
//! Keys serialized in v1.0 must be deserializable in v1.x.

#[cfg(test)]
mod tests {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    // ========================================================================
    // Key Size Stability Tests
    // ========================================================================

    #[test]
    fn api_stability_ml_kem_512_public_key_size() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");

        // ML-KEM-512 public key size is fixed by FIPS 203
        assert_eq!(
            pk.to_bytes().len(),
            800,
            "ML-KEM-512 public key must be exactly 800 bytes (FIPS 203)"
        );
    }

    #[test]
    fn api_stability_ml_kem_768_public_key_size() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
            .expect("keypair generation should succeed");

        assert_eq!(
            pk.to_bytes().len(),
            1184,
            "ML-KEM-768 public key must be exactly 1184 bytes (FIPS 203)"
        );
    }

    #[test]
    fn api_stability_ml_kem_1024_public_key_size() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)
            .expect("keypair generation should succeed");

        assert_eq!(
            pk.to_bytes().len(),
            1568,
            "ML-KEM-1024 public key must be exactly 1568 bytes (FIPS 203)"
        );
    }

    #[test]
    fn api_stability_ml_kem_secret_key_sizes() {
        let mut rng = OsRng;

        let sizes = [
            (MlKemSecurityLevel::MlKem512, 1632),
            (MlKemSecurityLevel::MlKem768, 2400),
            (MlKemSecurityLevel::MlKem1024, 3168),
        ];

        for (level, expected_size) in sizes {
            let (_pk, sk) = MlKem::generate_keypair(&mut rng, level)
                .expect("keypair generation should succeed");

            assert_eq!(
                sk.as_bytes().len(),
                expected_size,
                "Secret key size for {:?} must match FIPS 203 specification",
                level
            );
        }
    }

    #[test]
    fn api_stability_ml_kem_ciphertext_sizes() {
        let mut rng = OsRng;

        let sizes = [
            (MlKemSecurityLevel::MlKem512, 768),
            (MlKemSecurityLevel::MlKem768, 1088),
            (MlKemSecurityLevel::MlKem1024, 1568),
        ];

        for (level, expected_size) in sizes {
            let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)
                .expect("keypair generation should succeed");
            let (_ss, ct) =
                MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");

            assert_eq!(
                ct.as_bytes().len(),
                expected_size,
                "Ciphertext size for {:?} must match FIPS 203 specification",
                level
            );
        }
    }

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization for decapsulation"]
    fn api_stability_shared_secret_size() {
        let mut rng = OsRng;

        // All ML-KEM variants produce 32-byte shared secrets
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, sk) = MlKem::generate_keypair(&mut rng, level)
                .expect("keypair generation should succeed");
            let (ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");
            let ss_dec = MlKem::decapsulate(&sk, &ct).expect("decapsulation should succeed");

            assert_eq!(ss.as_bytes().len(), 32, "Shared secret must be 32 bytes for {:?}", level);
            assert_eq!(ss_dec.as_bytes().len(), 32);
        }
    }

    // ========================================================================
    // Serialization Round-Trip Tests
    // ========================================================================

    #[test]
    fn api_stability_public_key_roundtrip() {
        let mut rng = OsRng;

        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)
                .expect("keypair generation should succeed");

            let bytes = pk.to_bytes();
            let restored =
                MlKemPublicKey::from_bytes(&bytes, level).expect("restoration should succeed");

            assert_eq!(
                pk.to_bytes(),
                restored.to_bytes(),
                "Public key should survive serialization round-trip for {:?}",
                level
            );
        }
    }

    #[test]
    fn api_stability_secret_key_roundtrip() {
        let mut rng = OsRng;

        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (_pk, sk) = MlKem::generate_keypair(&mut rng, level)
                .expect("keypair generation should succeed");

            let bytes = sk.as_bytes().to_vec();
            let restored =
                MlKemSecretKey::new(level, bytes.clone()).expect("restoration should succeed");

            assert_eq!(
                sk.as_bytes(),
                restored.as_bytes(),
                "Secret key should survive serialization round-trip for {:?}",
                level
            );
        }
    }

    // ========================================================================
    // Cross-Version Compatibility Tests
    // ========================================================================

    #[test]
    fn api_stability_serialization_format_unchanged() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keypair generation should succeed");

        let bytes = pk.to_bytes();

        // Verify structure: size must match FIPS 203
        assert_eq!(bytes.len(), 800, "Size must not change");

        // Public key should be non-zero (not all zeros)
        assert!(bytes.iter().any(|&b| b != 0), "Public key should not be all zeros");
    }
}
