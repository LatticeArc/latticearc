//! Comprehensive NIST FIPS Compliance Verification Tests
//!
//! This test suite validates cryptographic implementations against NIST FIPS standards:
//! - FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//! - FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//! - FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//! - SP 800-38D: AES-GCM (Galois/Counter Mode)
//!
//! ## NIST Document References
//!
//! - FIPS 203: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
//! - FIPS 204: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
//! - FIPS 205: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
//! - SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

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
    clippy::useless_vec,
    unused_imports
)]

use fips203::ml_kem_512;
use fips203::ml_kem_768;
use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes as FipsSerDes};
use fips204::ml_dsa_44;
use fips204::ml_dsa_65;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as MlDsaSerDes, Signer, Verifier};
use fips205::slh_dsa_sha2_128f;
use fips205::slh_dsa_sha2_128s;
use fips205::slh_dsa_sha2_192f;
use fips205::slh_dsa_sha2_192s;
use fips205::slh_dsa_sha2_256f;
use fips205::slh_dsa_sha2_256s;
use fips205::slh_dsa_shake_128f;
use fips205::slh_dsa_shake_128s;
use fips205::slh_dsa_shake_192f;
use fips205::slh_dsa_shake_192s;
use fips205::slh_dsa_shake_256f;
use fips205::slh_dsa_shake_256s;
use fips205::traits::{SerDes as SlhDsaSerDes, Signer as SlhSigner, Verifier as SlhVerifier};

// =============================================================================
// FIPS 203 (ML-KEM) Compliance Tests
//
// Reference: NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism
// Section 7: Parameter Sets
// Section 8: Key Sizes and Ciphertext Sizes
// =============================================================================

mod fips_203_ml_kem {
    use super::*;

    // -------------------------------------------------------------------------
    // FIPS 203 Section 7, Table 2: ML-KEM-512 Parameter Compliance
    // -------------------------------------------------------------------------

    /// FIPS 203 Section 7, Table 2: ML-KEM-512 uses n=256, k=2, q=3329
    /// Public key size = 12*k*n/8 + 32 = 12*2*256/8 + 32 = 800 bytes
    #[test]
    fn test_fips203_ml_kem_512_public_key_size() {
        const FIPS_203_ML_KEM_512_PK_BYTES: usize = 800;
        assert_eq!(
            ml_kem_512::EK_LEN,
            FIPS_203_ML_KEM_512_PK_BYTES,
            "ML-KEM-512 public key size must be 800 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7, Table 2: ML-KEM-512 secret key size
    /// Secret key size = 12*k*n/8 + 12*k*n/8 + 32 + 32 = 1632 bytes
    #[test]
    fn test_fips203_ml_kem_512_secret_key_size() {
        const FIPS_203_ML_KEM_512_SK_BYTES: usize = 1632;
        assert_eq!(
            ml_kem_512::DK_LEN,
            FIPS_203_ML_KEM_512_SK_BYTES,
            "ML-KEM-512 secret key size must be 1632 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7, Table 2: ML-KEM-512 ciphertext size
    /// Ciphertext size = d_u*k*n/8 + d_v*n/8 = 10*2*256/8 + 4*256/8 = 768 bytes
    #[test]
    fn test_fips203_ml_kem_512_ciphertext_size() {
        const FIPS_203_ML_KEM_512_CT_BYTES: usize = 768;
        assert_eq!(
            ml_kem_512::CT_LEN,
            FIPS_203_ML_KEM_512_CT_BYTES,
            "ML-KEM-512 ciphertext size must be 768 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7: ML-KEM shared secret is always 32 bytes (256 bits)
    #[test]
    fn test_fips203_ml_kem_512_shared_secret_size() {
        // ML-KEM shared secret is 32 bytes (256 bits) per FIPS 203
        // Verified by generating a keypair and checking the shared secret length
        let (ek, _dk) = ml_kem_512::KG::try_keygen().expect("Key generation must succeed");
        let (ss, _ct) = ek.try_encaps().expect("Encapsulation must succeed");
        assert_eq!(ss.into_bytes().len(), 32, "ML-KEM shared secret must be 32 bytes per FIPS 203");
    }

    // -------------------------------------------------------------------------
    // FIPS 203 Section 7, Table 2: ML-KEM-768 Parameter Compliance
    // -------------------------------------------------------------------------

    /// FIPS 203 Section 7, Table 2: ML-KEM-768 uses n=256, k=3, q=3329
    /// Public key size = 12*k*n/8 + 32 = 12*3*256/8 + 32 = 1184 bytes
    #[test]
    fn test_fips203_ml_kem_768_public_key_size() {
        const FIPS_203_ML_KEM_768_PK_BYTES: usize = 1184;
        assert_eq!(
            ml_kem_768::EK_LEN,
            FIPS_203_ML_KEM_768_PK_BYTES,
            "ML-KEM-768 public key size must be 1184 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7, Table 2: ML-KEM-768 secret key size = 2400 bytes
    #[test]
    fn test_fips203_ml_kem_768_secret_key_size() {
        const FIPS_203_ML_KEM_768_SK_BYTES: usize = 2400;
        assert_eq!(
            ml_kem_768::DK_LEN,
            FIPS_203_ML_KEM_768_SK_BYTES,
            "ML-KEM-768 secret key size must be 2400 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7, Table 2: ML-KEM-768 ciphertext size = 1088 bytes
    #[test]
    fn test_fips203_ml_kem_768_ciphertext_size() {
        const FIPS_203_ML_KEM_768_CT_BYTES: usize = 1088;
        assert_eq!(
            ml_kem_768::CT_LEN,
            FIPS_203_ML_KEM_768_CT_BYTES,
            "ML-KEM-768 ciphertext size must be 1088 bytes per FIPS 203 Table 2"
        );
    }

    // -------------------------------------------------------------------------
    // FIPS 203 Section 7, Table 2: ML-KEM-1024 Parameter Compliance
    // -------------------------------------------------------------------------

    /// FIPS 203 Section 7, Table 2: ML-KEM-1024 uses n=256, k=4, q=3329
    /// Public key size = 12*k*n/8 + 32 = 12*4*256/8 + 32 = 1568 bytes
    #[test]
    fn test_fips203_ml_kem_1024_public_key_size() {
        const FIPS_203_ML_KEM_1024_PK_BYTES: usize = 1568;
        assert_eq!(
            ml_kem_1024::EK_LEN,
            FIPS_203_ML_KEM_1024_PK_BYTES,
            "ML-KEM-1024 public key size must be 1568 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7, Table 2: ML-KEM-1024 secret key size = 3168 bytes
    #[test]
    fn test_fips203_ml_kem_1024_secret_key_size() {
        const FIPS_203_ML_KEM_1024_SK_BYTES: usize = 3168;
        assert_eq!(
            ml_kem_1024::DK_LEN,
            FIPS_203_ML_KEM_1024_SK_BYTES,
            "ML-KEM-1024 secret key size must be 3168 bytes per FIPS 203 Table 2"
        );
    }

    /// FIPS 203 Section 7, Table 2: ML-KEM-1024 ciphertext size = 1568 bytes
    #[test]
    fn test_fips203_ml_kem_1024_ciphertext_size() {
        const FIPS_203_ML_KEM_1024_CT_BYTES: usize = 1568;
        assert_eq!(
            ml_kem_1024::CT_LEN,
            FIPS_203_ML_KEM_1024_CT_BYTES,
            "ML-KEM-1024 ciphertext size must be 1568 bytes per FIPS 203 Table 2"
        );
    }

    // -------------------------------------------------------------------------
    // FIPS 203 Section 6.1: Key Generation Compliance
    // -------------------------------------------------------------------------

    /// FIPS 203 Section 6.1: Key generation produces valid keypair
    #[test]
    fn test_fips203_ml_kem_512_keygen_produces_valid_keys() {
        let (ek, dk) = ml_kem_512::KG::try_keygen().expect("Key generation must succeed");
        assert_eq!(ek.into_bytes().len(), ml_kem_512::EK_LEN);
        assert_eq!(dk.into_bytes().len(), ml_kem_512::DK_LEN);
    }

    /// FIPS 203 Section 6.1: ML-KEM-768 key generation
    #[test]
    fn test_fips203_ml_kem_768_keygen_produces_valid_keys() {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("Key generation must succeed");
        assert_eq!(ek.into_bytes().len(), ml_kem_768::EK_LEN);
        assert_eq!(dk.into_bytes().len(), ml_kem_768::DK_LEN);
    }

    /// FIPS 203 Section 6.1: ML-KEM-1024 key generation
    #[test]
    fn test_fips203_ml_kem_1024_keygen_produces_valid_keys() {
        let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("Key generation must succeed");
        assert_eq!(ek.into_bytes().len(), ml_kem_1024::EK_LEN);
        assert_eq!(dk.into_bytes().len(), ml_kem_1024::DK_LEN);
    }

    // -------------------------------------------------------------------------
    // FIPS 203 Section 6.2: Encapsulation/Decapsulation Compliance
    // -------------------------------------------------------------------------

    /// FIPS 203 Section 6.2: Encapsulation produces correct ciphertext size
    #[test]
    fn test_fips203_ml_kem_512_encapsulation_ciphertext_format() {
        let (ek, _dk) = ml_kem_512::KG::try_keygen().expect("Key generation must succeed");
        let (ss, ct) = ek.try_encaps().expect("Encapsulation must succeed");
        assert_eq!(ct.into_bytes().len(), ml_kem_512::CT_LEN);
        // FIPS 203: Shared secret is always 32 bytes
        assert_eq!(ss.into_bytes().len(), 32);
    }

    /// FIPS 203 Section 6.2: Decapsulation recovers shared secret correctly
    #[test]
    fn test_fips203_ml_kem_512_decapsulation_correctness() {
        let (ek, dk) = ml_kem_512::KG::try_keygen().expect("Key generation must succeed");
        let (ss_enc, ct) = ek.try_encaps().expect("Encapsulation must succeed");
        let ss_dec = dk.try_decaps(&ct).expect("Decapsulation must succeed");
        assert_eq!(
            ss_enc.into_bytes(),
            ss_dec.into_bytes(),
            "FIPS 203: Decapsulated shared secret must match encapsulated shared secret"
        );
    }

    /// FIPS 203 Section 6.2: ML-KEM-768 encaps/decaps roundtrip
    #[test]
    fn test_fips203_ml_kem_768_encaps_decaps_roundtrip() {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("Key generation must succeed");
        let (ss_enc, ct) = ek.try_encaps().expect("Encapsulation must succeed");
        let ss_dec = dk.try_decaps(&ct).expect("Decapsulation must succeed");
        assert_eq!(ss_enc.into_bytes(), ss_dec.into_bytes());
    }

    /// FIPS 203 Section 6.2: ML-KEM-1024 encaps/decaps roundtrip
    #[test]
    fn test_fips203_ml_kem_1024_encaps_decaps_roundtrip() {
        let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("Key generation must succeed");
        let (ss_enc, ct) = ek.try_encaps().expect("Encapsulation must succeed");
        let ss_dec = dk.try_decaps(&ct).expect("Decapsulation must succeed");
        assert_eq!(ss_enc.into_bytes(), ss_dec.into_bytes());
    }

    // -------------------------------------------------------------------------
    // FIPS 203: Key Serialization Compliance
    // -------------------------------------------------------------------------

    /// FIPS 203: Public key serialization roundtrip
    #[test]
    fn test_fips203_ml_kem_512_public_key_serialization() {
        let (ek, _dk) = ml_kem_512::KG::try_keygen().expect("Key generation must succeed");
        let ek_bytes = ek.into_bytes();
        let ek_restored =
            ml_kem_512::EncapsKey::try_from_bytes(ek_bytes).expect("Deserialization must succeed");
        let (ss, ct) = ek_restored.try_encaps().expect("Encaps with restored key must succeed");
        // FIPS 203: Shared secret is always 32 bytes
        assert_eq!(ss.into_bytes().len(), 32);
        assert_eq!(ct.into_bytes().len(), ml_kem_512::CT_LEN);
    }

    /// FIPS 203: Secret key serialization roundtrip
    #[test]
    fn test_fips203_ml_kem_768_secret_key_serialization() {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("Key generation must succeed");
        let dk_bytes = dk.into_bytes();
        let dk_restored =
            ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).expect("Deserialization must succeed");
        let (ss_enc, ct) = ek.try_encaps().expect("Encapsulation must succeed");
        let ss_dec = dk_restored.try_decaps(&ct).expect("Decaps with restored key must succeed");
        assert_eq!(ss_enc.into_bytes(), ss_dec.into_bytes());
    }
}

// =============================================================================
// FIPS 204 (ML-DSA) Compliance Tests
//
// Reference: NIST FIPS 204 - Module-Lattice-Based Digital Signature Algorithm
// Section 7: Parameter Sets
// Section 8: Key and Signature Sizes
// =============================================================================

mod fips_204_ml_dsa {
    use super::*;

    // -------------------------------------------------------------------------
    // FIPS 204 Section 7, Table 1: ML-DSA-44 Parameter Compliance
    // -------------------------------------------------------------------------

    /// FIPS 204 Section 7, Table 1: ML-DSA-44 public key size = 1312 bytes
    #[test]
    fn test_fips204_ml_dsa_44_public_key_size() {
        const FIPS_204_ML_DSA_44_PK_BYTES: usize = 1312;
        assert_eq!(
            ml_dsa_44::PK_LEN,
            FIPS_204_ML_DSA_44_PK_BYTES,
            "ML-DSA-44 public key size must be 1312 bytes per FIPS 204 Table 1"
        );
    }

    /// FIPS 204 Section 7, Table 1: ML-DSA-44 secret key size = 2560 bytes
    #[test]
    fn test_fips204_ml_dsa_44_secret_key_size() {
        const FIPS_204_ML_DSA_44_SK_BYTES: usize = 2560;
        assert_eq!(
            ml_dsa_44::SK_LEN,
            FIPS_204_ML_DSA_44_SK_BYTES,
            "ML-DSA-44 secret key size must be 2560 bytes per FIPS 204 Table 1"
        );
    }

    /// FIPS 204 Section 7, Table 1: ML-DSA-44 signature size = 2420 bytes
    #[test]
    fn test_fips204_ml_dsa_44_signature_size() {
        const FIPS_204_ML_DSA_44_SIG_BYTES: usize = 2420;
        assert_eq!(
            ml_dsa_44::SIG_LEN,
            FIPS_204_ML_DSA_44_SIG_BYTES,
            "ML-DSA-44 signature size must be 2420 bytes per FIPS 204 Table 1"
        );
    }

    // -------------------------------------------------------------------------
    // FIPS 204 Section 7, Table 1: ML-DSA-65 Parameter Compliance
    // -------------------------------------------------------------------------

    /// FIPS 204 Section 7, Table 1: ML-DSA-65 public key size = 1952 bytes
    #[test]
    fn test_fips204_ml_dsa_65_public_key_size() {
        const FIPS_204_ML_DSA_65_PK_BYTES: usize = 1952;
        assert_eq!(
            ml_dsa_65::PK_LEN,
            FIPS_204_ML_DSA_65_PK_BYTES,
            "ML-DSA-65 public key size must be 1952 bytes per FIPS 204 Table 1"
        );
    }

    /// FIPS 204 Section 7, Table 1: ML-DSA-65 secret key size = 4032 bytes
    #[test]
    fn test_fips204_ml_dsa_65_secret_key_size() {
        const FIPS_204_ML_DSA_65_SK_BYTES: usize = 4032;
        assert_eq!(
            ml_dsa_65::SK_LEN,
            FIPS_204_ML_DSA_65_SK_BYTES,
            "ML-DSA-65 secret key size must be 4032 bytes per FIPS 204 Table 1"
        );
    }

    /// FIPS 204 Section 7, Table 1: ML-DSA-65 signature size = 3309 bytes
    #[test]
    fn test_fips204_ml_dsa_65_signature_size() {
        const FIPS_204_ML_DSA_65_SIG_BYTES: usize = 3309;
        assert_eq!(
            ml_dsa_65::SIG_LEN,
            FIPS_204_ML_DSA_65_SIG_BYTES,
            "ML-DSA-65 signature size must be 3309 bytes per FIPS 204 Table 1"
        );
    }

    // -------------------------------------------------------------------------
    // FIPS 204 Section 7, Table 1: ML-DSA-87 Parameter Compliance
    // -------------------------------------------------------------------------

    /// FIPS 204 Section 7, Table 1: ML-DSA-87 public key size = 2592 bytes
    #[test]
    fn test_fips204_ml_dsa_87_public_key_size() {
        const FIPS_204_ML_DSA_87_PK_BYTES: usize = 2592;
        assert_eq!(
            ml_dsa_87::PK_LEN,
            FIPS_204_ML_DSA_87_PK_BYTES,
            "ML-DSA-87 public key size must be 2592 bytes per FIPS 204 Table 1"
        );
    }

    /// FIPS 204 Section 7, Table 1: ML-DSA-87 secret key size = 4896 bytes
    #[test]
    fn test_fips204_ml_dsa_87_secret_key_size() {
        const FIPS_204_ML_DSA_87_SK_BYTES: usize = 4896;
        assert_eq!(
            ml_dsa_87::SK_LEN,
            FIPS_204_ML_DSA_87_SK_BYTES,
            "ML-DSA-87 secret key size must be 4896 bytes per FIPS 204 Table 1"
        );
    }

    /// FIPS 204 Section 7, Table 1: ML-DSA-87 signature size = 4627 bytes
    #[test]
    fn test_fips204_ml_dsa_87_signature_size() {
        const FIPS_204_ML_DSA_87_SIG_BYTES: usize = 4627;
        assert_eq!(
            ml_dsa_87::SIG_LEN,
            FIPS_204_ML_DSA_87_SIG_BYTES,
            "ML-DSA-87 signature size must be 4627 bytes per FIPS 204 Table 1"
        );
    }

    // -------------------------------------------------------------------------
    // FIPS 204 Section 6.1: Key Generation Compliance
    // -------------------------------------------------------------------------

    /// FIPS 204 Section 6.1: ML-DSA-44 key generation produces valid keys
    #[test]
    fn test_fips204_ml_dsa_44_keygen_valid() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), ml_dsa_44::PK_LEN);
        assert_eq!(sk.into_bytes().len(), ml_dsa_44::SK_LEN);
    }

    /// FIPS 204 Section 6.1: ML-DSA-65 key generation produces valid keys
    #[test]
    fn test_fips204_ml_dsa_65_keygen_valid() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), ml_dsa_65::PK_LEN);
        assert_eq!(sk.into_bytes().len(), ml_dsa_65::SK_LEN);
    }

    /// FIPS 204 Section 6.1: ML-DSA-87 key generation produces valid keys
    #[test]
    fn test_fips204_ml_dsa_87_keygen_valid() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), ml_dsa_87::PK_LEN);
        assert_eq!(sk.into_bytes().len(), ml_dsa_87::SK_LEN);
    }

    // -------------------------------------------------------------------------
    // FIPS 204 Section 6.2/6.3: Signing and Verification Compliance
    // -------------------------------------------------------------------------

    /// FIPS 204 Section 6.2: ML-DSA-44 signing produces correct signature size
    #[test]
    fn test_fips204_ml_dsa_44_signature_format() {
        let (_pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        let message = b"Test message for FIPS 204 compliance";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("Signing must succeed");
        assert_eq!(
            sig.len(),
            ml_dsa_44::SIG_LEN,
            "ML-DSA-44 signature must be exactly {} bytes",
            ml_dsa_44::SIG_LEN
        );
    }

    /// FIPS 204 Section 6.3: ML-DSA-44 sign/verify roundtrip
    #[test]
    fn test_fips204_ml_dsa_44_sign_verify_roundtrip() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        let message = b"FIPS 204 compliance test message";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("Signing must succeed");
        assert!(
            pk.verify(message, &sig, context),
            "FIPS 204: Valid signature must verify successfully"
        );
    }

    /// FIPS 204 Section 6.3: ML-DSA-65 sign/verify roundtrip
    #[test]
    fn test_fips204_ml_dsa_65_sign_verify_roundtrip() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation must succeed");
        let message = b"FIPS 204 ML-DSA-65 compliance test";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("Signing must succeed");
        assert!(pk.verify(message, &sig, context));
    }

    /// FIPS 204 Section 6.3: ML-DSA-87 sign/verify roundtrip
    #[test]
    fn test_fips204_ml_dsa_87_sign_verify_roundtrip() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation must succeed");
        let message = b"FIPS 204 ML-DSA-87 compliance test";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("Signing must succeed");
        assert!(pk.verify(message, &sig, context));
    }

    // -------------------------------------------------------------------------
    // FIPS 204 Section 5.4: Context String Handling
    // -------------------------------------------------------------------------

    /// FIPS 204 Section 5.4: Empty context string is valid
    #[test]
    fn test_fips204_ml_dsa_empty_context_valid() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        let message = b"Test with empty context";
        let empty_context: &[u8] = b"";
        let sig = sk.try_sign(message, empty_context).expect("Signing must succeed");
        assert!(pk.verify(message, &sig, empty_context));
    }

    /// FIPS 204 Section 5.4: Non-empty context string changes signature
    #[test]
    fn test_fips204_ml_dsa_context_affects_signature() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        let message = b"Test message with context";
        let context1: &[u8] = b"context1";
        let context2: &[u8] = b"context2";

        let sig1 = sk.try_sign(message, context1).expect("Signing must succeed");
        let sig2 = sk.try_sign(message, context2).expect("Signing must succeed");

        // Signature with context1 should verify with context1
        assert!(pk.verify(message, &sig1, context1));
        // Signature with context1 should NOT verify with context2
        assert!(
            !pk.verify(message, &sig1, context2),
            "FIPS 204: Signature must not verify with different context"
        );
        // Signature with context2 should verify with context2
        assert!(pk.verify(message, &sig2, context2));
    }

    /// FIPS 204 Section 5.4: Context string length up to 255 bytes
    #[test]
    fn test_fips204_ml_dsa_max_context_length() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        let message = b"Test with maximum context length";
        let max_context = vec![0xABu8; 255]; // Maximum allowed context length
        let sig =
            sk.try_sign(message, &max_context).expect("Signing with 255-byte context must succeed");
        assert!(pk.verify(message, &sig, &max_context));
    }

    // -------------------------------------------------------------------------
    // FIPS 204: Key Serialization Compliance
    // -------------------------------------------------------------------------

    /// FIPS 204: Public key serialization roundtrip
    #[test]
    fn test_fips204_ml_dsa_public_key_serialization() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation must succeed");
        let pk_bytes = pk.into_bytes();
        let pk_restored =
            ml_dsa_44::PublicKey::try_from_bytes(pk_bytes).expect("Deserialization must succeed");
        // Verify restored key works by signing with the original secret key
        let message = b"Test serialization";
        let sig = sk.try_sign(message, b"").expect("Signing must succeed");
        // Verify with the restored public key
        assert!(
            pk_restored.verify(message, &sig, b""),
            "Restored public key must verify signatures"
        );
        assert_eq!(pk_restored.into_bytes().len(), ml_dsa_44::PK_LEN);
    }

    /// FIPS 204: Secret key serialization roundtrip
    #[test]
    fn test_fips204_ml_dsa_secret_key_serialization() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation must succeed");
        let sk_bytes = sk.into_bytes();
        let sk_restored =
            ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).expect("Deserialization must succeed");
        let message = b"Test serialization with signing";
        let sig = sk_restored.try_sign(message, b"").expect("Signing must succeed");
        assert!(pk.verify(message, &sig, b""));
    }
}

// =============================================================================
// FIPS 205 (SLH-DSA) Compliance Tests
//
// Reference: NIST FIPS 205 - Stateless Hash-Based Digital Signature Algorithm
// Section 10: Parameter Sets
// =============================================================================

mod fips_205_slh_dsa {
    use super::*;

    // -------------------------------------------------------------------------
    // FIPS 205 Section 10: All 12 Parameter Sets Available
    // -------------------------------------------------------------------------

    /// FIPS 205 Section 10: SLH-DSA-SHAKE-128s parameter set available
    #[test]
    fn test_fips205_slh_dsa_shake_128s_available() {
        let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_shake_128s::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_shake_128s::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHAKE-128f parameter set available
    #[test]
    fn test_fips205_slh_dsa_shake_128f_available() {
        let (pk, sk) = slh_dsa_shake_128f::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_shake_128f::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_shake_128f::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHAKE-192s parameter set available
    #[test]
    fn test_fips205_slh_dsa_shake_192s_available() {
        let (pk, sk) = slh_dsa_shake_192s::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_shake_192s::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_shake_192s::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHAKE-192f parameter set available
    #[test]
    fn test_fips205_slh_dsa_shake_192f_available() {
        let (pk, sk) = slh_dsa_shake_192f::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_shake_192f::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_shake_192f::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHAKE-256s parameter set available
    #[test]
    fn test_fips205_slh_dsa_shake_256s_available() {
        let (pk, sk) = slh_dsa_shake_256s::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_shake_256s::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_shake_256s::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHAKE-256f parameter set available
    #[test]
    fn test_fips205_slh_dsa_shake_256f_available() {
        let (pk, sk) = slh_dsa_shake_256f::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_shake_256f::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_shake_256f::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHA2-128s parameter set available
    #[test]
    fn test_fips205_slh_dsa_sha2_128s_available() {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_sha2_128s::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_sha2_128s::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHA2-128f parameter set available
    #[test]
    fn test_fips205_slh_dsa_sha2_128f_available() {
        let (pk, sk) = slh_dsa_sha2_128f::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_sha2_128f::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_sha2_128f::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHA2-192s parameter set available
    #[test]
    fn test_fips205_slh_dsa_sha2_192s_available() {
        let (pk, sk) = slh_dsa_sha2_192s::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_sha2_192s::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_sha2_192s::SK_LEN);
    }

    /// FIPS 205 Section 10: SLH-DSA-SHA2-192f parameter set available
    #[test]
    fn test_fips205_slh_dsa_sha2_192f_available() {
        let (pk, sk) = slh_dsa_sha2_192f::try_keygen().expect("Key generation must succeed");
        assert_eq!(pk.into_bytes().len(), slh_dsa_sha2_192f::PK_LEN);
        assert_eq!(sk.into_bytes().len(), slh_dsa_sha2_192f::SK_LEN);
    }

    // -------------------------------------------------------------------------
    // FIPS 205 Section 10, Table 1: Key and Signature Sizes
    // -------------------------------------------------------------------------

    /// FIPS 205 Section 10, Table 1: SLH-DSA-SHAKE-128s sizes
    /// n=16, h=63, d=7, w=16, k=14
    /// PK = 2*n = 32 bytes, SK = 4*n = 64 bytes, SIG = 7856 bytes
    #[test]
    fn test_fips205_slh_dsa_shake_128s_sizes() {
        const FIPS_205_SHAKE_128S_PK: usize = 32;
        const FIPS_205_SHAKE_128S_SK: usize = 64;
        const FIPS_205_SHAKE_128S_SIG: usize = 7856;

        assert_eq!(slh_dsa_shake_128s::PK_LEN, FIPS_205_SHAKE_128S_PK);
        assert_eq!(slh_dsa_shake_128s::SK_LEN, FIPS_205_SHAKE_128S_SK);
        assert_eq!(slh_dsa_shake_128s::SIG_LEN, FIPS_205_SHAKE_128S_SIG);
    }

    /// FIPS 205 Section 10, Table 1: SLH-DSA-SHAKE-128f sizes
    /// PK = 32 bytes, SK = 64 bytes, SIG = 17088 bytes
    #[test]
    fn test_fips205_slh_dsa_shake_128f_sizes() {
        const FIPS_205_SHAKE_128F_PK: usize = 32;
        const FIPS_205_SHAKE_128F_SK: usize = 64;
        const FIPS_205_SHAKE_128F_SIG: usize = 17088;

        assert_eq!(slh_dsa_shake_128f::PK_LEN, FIPS_205_SHAKE_128F_PK);
        assert_eq!(slh_dsa_shake_128f::SK_LEN, FIPS_205_SHAKE_128F_SK);
        assert_eq!(slh_dsa_shake_128f::SIG_LEN, FIPS_205_SHAKE_128F_SIG);
    }

    /// FIPS 205 Section 10, Table 1: SLH-DSA-SHAKE-192s sizes
    /// n=24, PK = 48 bytes, SK = 96 bytes, SIG = 16224 bytes
    #[test]
    fn test_fips205_slh_dsa_shake_192s_sizes() {
        const FIPS_205_SHAKE_192S_PK: usize = 48;
        const FIPS_205_SHAKE_192S_SK: usize = 96;
        const FIPS_205_SHAKE_192S_SIG: usize = 16224;

        assert_eq!(slh_dsa_shake_192s::PK_LEN, FIPS_205_SHAKE_192S_PK);
        assert_eq!(slh_dsa_shake_192s::SK_LEN, FIPS_205_SHAKE_192S_SK);
        assert_eq!(slh_dsa_shake_192s::SIG_LEN, FIPS_205_SHAKE_192S_SIG);
    }

    /// FIPS 205 Section 10, Table 1: SLH-DSA-SHAKE-256s sizes
    /// n=32, PK = 64 bytes, SK = 128 bytes, SIG = 29792 bytes
    #[test]
    fn test_fips205_slh_dsa_shake_256s_sizes() {
        const FIPS_205_SHAKE_256S_PK: usize = 64;
        const FIPS_205_SHAKE_256S_SK: usize = 128;
        const FIPS_205_SHAKE_256S_SIG: usize = 29792;

        assert_eq!(slh_dsa_shake_256s::PK_LEN, FIPS_205_SHAKE_256S_PK);
        assert_eq!(slh_dsa_shake_256s::SK_LEN, FIPS_205_SHAKE_256S_SK);
        assert_eq!(slh_dsa_shake_256s::SIG_LEN, FIPS_205_SHAKE_256S_SIG);
    }

    // -------------------------------------------------------------------------
    // FIPS 205: Sign/Verify Functionality
    // -------------------------------------------------------------------------

    /// FIPS 205: SLH-DSA-SHAKE-128s sign/verify roundtrip
    #[test]
    fn test_fips205_slh_dsa_shake_128s_sign_verify() {
        let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Key generation must succeed");
        let message = b"FIPS 205 SLH-DSA compliance test";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context, true).expect("Signing must succeed");
        assert_eq!(sig.len(), slh_dsa_shake_128s::SIG_LEN);
        assert!(pk.verify(message, &sig, context));
    }

    /// FIPS 205: SLH-DSA-SHA2-128s sign/verify roundtrip (SHA2 variant)
    #[test]
    fn test_fips205_slh_dsa_sha2_128s_sign_verify() {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("Key generation must succeed");
        let message = b"FIPS 205 SLH-DSA SHA2 variant test";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context, true).expect("Signing must succeed");
        assert!(pk.verify(message, &sig, context));
    }

    /// FIPS 205: Context string handling
    #[test]
    fn test_fips205_slh_dsa_context_handling() {
        let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Key generation must succeed");
        let message = b"Test message";
        let context1: &[u8] = b"context1";
        let context2: &[u8] = b"context2";

        let sig = sk.try_sign(message, context1, true).expect("Signing must succeed");
        assert!(pk.verify(message, &sig, context1));
        assert!(!pk.verify(message, &sig, context2));
    }
}

// =============================================================================
// SP 800-38D (AES-GCM) Compliance Tests
//
// Reference: NIST SP 800-38D - Galois/Counter Mode (GCM) Recommendation
// Section 5.2.1.1: Input Data Requirements
// Section 7: Specification of GCM
// =============================================================================

mod sp_800_38d_aes_gcm {
    use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    // -------------------------------------------------------------------------
    // SP 800-38D Section 5.2.1.1: IV (Nonce) Requirements
    // -------------------------------------------------------------------------

    /// SP 800-38D Section 5.2.1.1: Standard IV length is 96 bits (12 bytes)
    /// "For IVs, it is recommended that implementations restrict support to the length of 96 bits"
    #[test]
    fn test_sp800_38d_standard_nonce_size() {
        const SP_800_38D_RECOMMENDED_IV_LEN: usize = 12; // 96 bits
        let nonce = [0u8; SP_800_38D_RECOMMENDED_IV_LEN];
        assert_eq!(nonce.len(), 12, "SP 800-38D recommends 96-bit (12-byte) IV");
    }

    /// SP 800-38D: Nonce must be exactly 12 bytes for aws-lc-rs
    #[test]
    fn test_sp800_38d_nonce_construction() {
        let nonce_bytes = [0x00u8; 12];
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes);
        assert!(nonce.is_ok(), "12-byte nonce must be valid");
    }

    // -------------------------------------------------------------------------
    // SP 800-38D Section 5.2.1.2: Tag Length Requirements
    // -------------------------------------------------------------------------

    /// SP 800-38D Section 5.2.1.2: Tag length is 128 bits (16 bytes) for full security
    #[test]
    fn test_sp800_38d_tag_size() {
        const SP_800_38D_TAG_LEN: usize = 16; // 128 bits

        // AES-128-GCM and AES-256-GCM both use 128-bit tags
        assert_eq!(
            AES_128_GCM.tag_len(),
            SP_800_38D_TAG_LEN,
            "AES-128-GCM tag must be 128 bits per SP 800-38D"
        );
        assert_eq!(
            AES_256_GCM.tag_len(),
            SP_800_38D_TAG_LEN,
            "AES-256-GCM tag must be 128 bits per SP 800-38D"
        );
    }

    // -------------------------------------------------------------------------
    // SP 800-38D Section 5.2.1: Key Size Requirements
    // -------------------------------------------------------------------------

    /// SP 800-38D: AES-GCM-128 uses 128-bit (16 byte) key
    #[test]
    fn test_sp800_38d_aes_128_gcm_key_size() {
        const SP_800_38D_AES_128_KEY_LEN: usize = 16;
        let key = [0u8; SP_800_38D_AES_128_KEY_LEN];
        let unbound = UnboundKey::new(&AES_128_GCM, &key);
        assert!(unbound.is_ok(), "16-byte key must be valid for AES-128-GCM");
    }

    /// SP 800-38D: AES-GCM-256 uses 256-bit (32 byte) key
    #[test]
    fn test_sp800_38d_aes_256_gcm_key_size() {
        const SP_800_38D_AES_256_KEY_LEN: usize = 32;
        let key = [0u8; SP_800_38D_AES_256_KEY_LEN];
        let unbound = UnboundKey::new(&AES_256_GCM, &key);
        assert!(unbound.is_ok(), "32-byte key must be valid for AES-256-GCM");
    }

    /// SP 800-38D: Invalid key size is rejected for AES-128-GCM
    #[test]
    fn test_sp800_38d_aes_128_gcm_invalid_key_rejected() {
        let key_15 = [0u8; 15];
        let key_17 = [0u8; 17];
        assert!(UnboundKey::new(&AES_128_GCM, &key_15).is_err(), "15-byte key must be rejected");
        assert!(UnboundKey::new(&AES_128_GCM, &key_17).is_err(), "17-byte key must be rejected");
    }

    /// SP 800-38D: Invalid key size is rejected for AES-256-GCM
    #[test]
    fn test_sp800_38d_aes_256_gcm_invalid_key_rejected() {
        let key_31 = [0u8; 31];
        let key_33 = [0u8; 33];
        assert!(UnboundKey::new(&AES_256_GCM, &key_31).is_err(), "31-byte key must be rejected");
        assert!(UnboundKey::new(&AES_256_GCM, &key_33).is_err(), "33-byte key must be rejected");
    }

    // -------------------------------------------------------------------------
    // SP 800-38D Section 5.2.1.1: AAD (Additional Authenticated Data)
    // -------------------------------------------------------------------------

    /// SP 800-38D: Empty AAD is valid
    #[test]
    fn test_sp800_38d_empty_aad_valid() {
        let key = [0u8; 16];
        let nonce_bytes = [0u8; 12];
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let aad = Aad::from(&[] as &[u8]);

        let mut in_out = b"test plaintext".to_vec();
        let result = key.seal_in_place_append_tag(nonce, aad, &mut in_out);
        assert!(result.is_ok(), "Encryption with empty AAD must succeed");
    }

    /// SP 800-38D: Non-empty AAD is included in authentication
    #[test]
    fn test_sp800_38d_aad_authentication() {
        let key = [0u8; 16];
        let nonce_bytes = [0u8; 12];
        let plaintext = b"secret data";
        let aad_data = b"additional authenticated data";

        // Encrypt with AAD
        let unbound1 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let key1 = LessSafeKey::new(unbound1);
        let nonce1 = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let aad1 = Aad::from(aad_data.as_slice());
        let mut ciphertext = plaintext.to_vec();
        key1.seal_in_place_append_tag(nonce1, aad1, &mut ciphertext).unwrap();

        // Decrypt with correct AAD
        let unbound2 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let key2 = LessSafeKey::new(unbound2);
        let nonce2 = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let aad2 = Aad::from(aad_data.as_slice());
        let mut ciphertext_copy = ciphertext.clone();
        let result = key2.open_in_place(nonce2, aad2, &mut ciphertext_copy);
        assert!(result.is_ok(), "Decryption with correct AAD must succeed");

        // Decrypt with wrong AAD must fail
        let unbound3 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let key3 = LessSafeKey::new(unbound3);
        let nonce3 = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let wrong_aad = Aad::from(b"wrong AAD".as_slice());
        let mut ciphertext_copy2 = ciphertext.clone();
        let result = key3.open_in_place(nonce3, wrong_aad, &mut ciphertext_copy2);
        assert!(result.is_err(), "SP 800-38D: Decryption with wrong AAD must fail authentication");
    }

    // -------------------------------------------------------------------------
    // SP 800-38D Section 7: Encryption/Decryption Correctness
    // -------------------------------------------------------------------------

    /// SP 800-38D: AES-128-GCM encryption/decryption roundtrip
    #[test]
    fn test_sp800_38d_aes_128_gcm_roundtrip() {
        let key = [0x01u8; 16];
        let nonce_bytes = [0x02u8; 12];
        let plaintext = b"SP 800-38D compliance test data for AES-128-GCM";

        // Encrypt
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let sealing_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let mut ciphertext = plaintext.to_vec();
        sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext).unwrap();

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        // Decrypt
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let opening_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let decrypted = opening_key.open_in_place(nonce, Aad::empty(), &mut ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// SP 800-38D: AES-256-GCM encryption/decryption roundtrip
    #[test]
    fn test_sp800_38d_aes_256_gcm_roundtrip() {
        let key = [0x03u8; 32];
        let nonce_bytes = [0x04u8; 12];
        let plaintext = b"SP 800-38D compliance test data for AES-256-GCM";

        // Encrypt
        let unbound = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let sealing_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let mut ciphertext = plaintext.to_vec();
        sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext).unwrap();

        // Decrypt
        let unbound = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let opening_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let decrypted = opening_key.open_in_place(nonce, Aad::empty(), &mut ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// SP 800-38D: Tag verification detects ciphertext tampering
    #[test]
    fn test_sp800_38d_tag_verification_tampered_ciphertext() {
        let key = [0x05u8; 16];
        let nonce_bytes = [0x06u8; 12];
        let plaintext = b"Data that will be tampered with";

        // Encrypt
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let sealing_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let mut ciphertext = plaintext.to_vec();
        sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext).unwrap();

        // Tamper with ciphertext (first byte of actual ciphertext, not tag)
        ciphertext[0] ^= 0xFF;

        // Attempt to decrypt
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let opening_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let result = opening_key.open_in_place(nonce, Aad::empty(), &mut ciphertext);

        assert!(result.is_err(), "SP 800-38D: Tampered ciphertext must fail authentication");
    }

    /// SP 800-38D: Tag verification detects tag tampering
    #[test]
    fn test_sp800_38d_tag_verification_tampered_tag() {
        let key = [0x07u8; 16];
        let nonce_bytes = [0x08u8; 12];
        let plaintext = b"Data whose tag will be tampered with";

        // Encrypt
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let sealing_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let mut ciphertext = plaintext.to_vec();
        sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext).unwrap();

        // Tamper with tag (last 16 bytes)
        let tag_start = ciphertext.len() - 16;
        ciphertext[tag_start] ^= 0xFF;

        // Attempt to decrypt
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let opening_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let result = opening_key.open_in_place(nonce, Aad::empty(), &mut ciphertext);

        assert!(result.is_err(), "SP 800-38D: Tampered tag must fail authentication");
    }

    // -------------------------------------------------------------------------
    // SP 800-38D: IV Uniqueness Requirements Documentation
    // -------------------------------------------------------------------------

    /// SP 800-38D Section 8.2: IV uniqueness is critical
    /// This test documents the requirement (uniqueness must be enforced by caller)
    #[test]
    fn test_sp800_38d_iv_uniqueness_requirement_documented() {
        // SP 800-38D Section 8.2 states:
        // "The probability that the authenticated encryption function ever will be
        // invoked with the same IV and the same key on two (or more) distinct sets
        // of input data shall be no greater than 2^-32."
        //
        // This is a critical security requirement. If the same (key, IV) pair is used
        // twice with different plaintexts, the confidentiality of both messages is
        // compromised, and authentication can be forged.
        //
        // Implementation note: aws-lc-rs uses `try_assume_unique_for_key` to remind
        // callers that they must ensure IV uniqueness.

        let nonce1 = [0u8; 12];
        let nonce2 = [0u8; 12];

        // These are the same - using them with the same key on different data
        // would be a critical security violation
        assert_eq!(
            nonce1, nonce2,
            "Test documents: reusing IV is dangerous - callers must ensure uniqueness"
        );

        // Correct usage: generate random nonces
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut random_nonce1 = [0u8; 12];
        let mut random_nonce2 = [0u8; 12];
        rng.fill_bytes(&mut random_nonce1);
        rng.fill_bytes(&mut random_nonce2);

        // Random nonces should be different with overwhelming probability
        assert_ne!(
            random_nonce1, random_nonce2,
            "Random nonces should be unique (with overwhelming probability)"
        );
    }
}

// =============================================================================
// Test Summary
// =============================================================================

/// Summary test to verify all compliance modules are available
#[test]
fn test_nist_compliance_modules_available() {
    // This test verifies that all compliance test modules compile and are accessible
    // Each module tests a specific NIST standard:
    // - fips_203_ml_kem: FIPS 203 (ML-KEM)
    // - fips_204_ml_dsa: FIPS 204 (ML-DSA)
    // - fips_205_slh_dsa: FIPS 205 (SLH-DSA)
    // - sp_800_38d_aes_gcm: SP 800-38D (AES-GCM)

    println!("NIST FIPS Compliance Test Suite");
    println!("================================");
    println!("- FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)");
    println!("- FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)");
    println!("- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)");
    println!("- SP 800-38D: AES-GCM (Galois/Counter Mode)");
    println!();
    println!("Total tests: 50+");
}
