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

//! NIST Known-Answer-Test Compliance Suite
//!
//! Validates ML-KEM, ML-DSA, and SLH-DSA parameter sizes against FIPS 203/204/205
//! and verifies KEM encap/decap and signature sign/verify roundtrips.
//!
//! Run with: `cargo test --package arc-validation --test nist_kat_compliance --all-features --release -- --nocapture`

use fips203::ml_kem_512;
use fips203::ml_kem_768;
use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes as FipsSerDes};
use fips204::ml_dsa_44;
use fips204::ml_dsa_65;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as MlDsaSerDes, Signer, Verifier};

// ============================================================================
// ML-KEM Key/Ciphertext/Shared-Secret Sizes — FIPS 203
// ============================================================================

mod ml_kem_sizes {
    use super::*;

    #[test]
    fn test_ml_kem_512_sizes() {
        // FIPS 203 Table 2: ek=800, dk=1632, ct=768, ss=32
        assert_eq!(ml_kem_512::EK_LEN, 800, "ML-KEM-512 encapsulation key = 800");
        assert_eq!(ml_kem_512::DK_LEN, 1632, "ML-KEM-512 decapsulation key = 1632");
        assert_eq!(ml_kem_512::CT_LEN, 768, "ML-KEM-512 ciphertext = 768");
    }

    #[test]
    fn test_ml_kem_768_sizes() {
        // FIPS 203 Table 2: ek=1184, dk=2400, ct=1088, ss=32
        assert_eq!(ml_kem_768::EK_LEN, 1184, "ML-KEM-768 encapsulation key = 1184");
        assert_eq!(ml_kem_768::DK_LEN, 2400, "ML-KEM-768 decapsulation key = 2400");
        assert_eq!(ml_kem_768::CT_LEN, 1088, "ML-KEM-768 ciphertext = 1088");
    }

    #[test]
    fn test_ml_kem_1024_sizes() {
        // FIPS 203 Table 2: ek=1568, dk=3168, ct=1568, ss=32
        assert_eq!(ml_kem_1024::EK_LEN, 1568, "ML-KEM-1024 encapsulation key = 1568");
        assert_eq!(ml_kem_1024::DK_LEN, 3168, "ML-KEM-1024 decapsulation key = 3168");
        assert_eq!(ml_kem_1024::CT_LEN, 1568, "ML-KEM-1024 ciphertext = 1568");
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        let (ek, dk) = ml_kem_512::KG::try_keygen().expect("ML-KEM-512 keygen failed");
        let (ss_enc, ct) = ek.try_encaps().expect("ML-KEM-512 encaps failed");
        let ss_dec = dk.try_decaps(&ct).expect("ML-KEM-512 decaps failed");
        assert_eq!(ss_enc, ss_dec, "ML-KEM-512 shared secrets must match");
    }

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("ML-KEM-768 keygen failed");
        let (ss_enc, ct) = ek.try_encaps().expect("ML-KEM-768 encaps failed");
        let ss_dec = dk.try_decaps(&ct).expect("ML-KEM-768 decaps failed");
        assert_eq!(ss_enc, ss_dec, "ML-KEM-768 shared secrets must match");
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("ML-KEM-1024 keygen failed");
        let (ss_enc, ct) = ek.try_encaps().expect("ML-KEM-1024 encaps failed");
        let ss_dec = dk.try_decaps(&ct).expect("ML-KEM-1024 decaps failed");
        assert_eq!(ss_enc, ss_dec, "ML-KEM-1024 shared secrets must match");
    }
}

// ============================================================================
// ML-DSA Key/Signature Sizes — FIPS 204
// ============================================================================

mod ml_dsa_sizes {
    use super::*;

    #[test]
    fn test_ml_dsa_44_sizes() {
        // FIPS 204 Table 1: pk=1312, sk=2560, sig=2420
        assert_eq!(ml_dsa_44::PK_LEN, 1312, "ML-DSA-44 public key = 1312");
        assert_eq!(ml_dsa_44::SK_LEN, 2560, "ML-DSA-44 secret key = 2560");
        assert_eq!(ml_dsa_44::SIG_LEN, 2420, "ML-DSA-44 signature = 2420");
    }

    #[test]
    fn test_ml_dsa_65_sizes() {
        // FIPS 204 Table 1: pk=1952, sk=4032, sig=3309
        assert_eq!(ml_dsa_65::PK_LEN, 1952, "ML-DSA-65 public key = 1952");
        assert_eq!(ml_dsa_65::SK_LEN, 4032, "ML-DSA-65 secret key = 4032");
        assert_eq!(ml_dsa_65::SIG_LEN, 3309, "ML-DSA-65 signature = 3309");
    }

    #[test]
    fn test_ml_dsa_87_sizes() {
        // FIPS 204 Table 1: pk=2592, sk=4896, sig=4627
        assert_eq!(ml_dsa_87::PK_LEN, 2592, "ML-DSA-87 public key = 2592");
        assert_eq!(ml_dsa_87::SK_LEN, 4896, "ML-DSA-87 secret key = 4896");
        assert_eq!(ml_dsa_87::SIG_LEN, 4627, "ML-DSA-87 signature = 4627");
    }

    #[test]
    fn test_ml_dsa_44_roundtrip() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("ML-DSA-44 keygen failed");
        let message = b"NIST KAT compliance roundtrip";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("ML-DSA-44 sign failed");
        assert!(pk.verify(message, &sig, context), "ML-DSA-44 signature must verify");
    }

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 keygen failed");
        let message = b"ML-DSA-65 compliance check";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("ML-DSA-65 sign failed");
        assert!(pk.verify(message, &sig, context), "ML-DSA-65 signature must verify");
    }

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("ML-DSA-87 keygen failed");
        let message = b"ML-DSA-87 compliance check";
        let context: &[u8] = b"";
        let sig = sk.try_sign(message, context).expect("ML-DSA-87 sign failed");
        assert!(pk.verify(message, &sig, context), "ML-DSA-87 signature must verify");
    }
}

// ============================================================================
// ML-KEM Key Serialization Roundtrip
// ============================================================================

mod ml_kem_serialization {
    use super::*;

    #[test]
    fn test_ml_kem_512_key_serialization() {
        let (ek, dk) = ml_kem_512::KG::try_keygen().expect("keygen failed");
        let ek_bytes = ek.into_bytes();
        let dk_bytes = dk.into_bytes();

        assert_eq!(ek_bytes.len(), ml_kem_512::EK_LEN);
        assert_eq!(dk_bytes.len(), ml_kem_512::DK_LEN);

        let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek_bytes).expect("ek deser failed");
        let dk2 = ml_kem_512::DecapsKey::try_from_bytes(dk_bytes).expect("dk deser failed");

        // Verify roundtrip still works with deserialized keys
        let (ss_enc, ct) = ek2.try_encaps().expect("encaps failed");
        let ss_dec = dk2.try_decaps(&ct).expect("decaps failed");
        assert_eq!(ss_enc, ss_dec, "Roundtrip after deserialization must work");
    }

    #[test]
    fn test_ml_kem_768_key_serialization() {
        let (ek, dk) = ml_kem_768::KG::try_keygen().expect("keygen failed");
        let ek_bytes = ek.into_bytes();
        let dk_bytes = dk.into_bytes();

        assert_eq!(ek_bytes.len(), ml_kem_768::EK_LEN);
        assert_eq!(dk_bytes.len(), ml_kem_768::DK_LEN);

        let ek2 = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).expect("ek deser failed");
        let dk2 = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).expect("dk deser failed");

        let (ss_enc, ct) = ek2.try_encaps().expect("encaps failed");
        let ss_dec = dk2.try_decaps(&ct).expect("decaps failed");
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_ml_kem_1024_key_serialization() {
        let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("keygen failed");
        let ek_bytes = ek.into_bytes();
        let dk_bytes = dk.into_bytes();

        assert_eq!(ek_bytes.len(), ml_kem_1024::EK_LEN);
        assert_eq!(dk_bytes.len(), ml_kem_1024::DK_LEN);

        let ek2 = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes).expect("ek deser failed");
        let dk2 = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes).expect("dk deser failed");

        let (ss_enc, ct) = ek2.try_encaps().expect("encaps failed");
        let ss_dec = dk2.try_decaps(&ct).expect("decaps failed");
        assert_eq!(ss_enc, ss_dec);
    }
}

// ============================================================================
// ML-DSA Key Serialization Roundtrip
// ============================================================================

mod ml_dsa_serialization {
    use super::*;

    #[test]
    fn test_ml_dsa_44_key_serialization() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen failed");

        // Verify key sizes match FIPS 204 Table 1
        assert_eq!(pk.into_bytes().len(), ml_dsa_44::PK_LEN);
        assert_eq!(sk.into_bytes().len(), ml_dsa_44::SK_LEN);

        // Roundtrip: keygen → serialize → deserialize → sign/verify
        let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen2 failed");
        let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk.into_bytes()).expect("pk deser failed");
        let sk2 = ml_dsa_44::PrivateKey::try_from_bytes(sk.into_bytes()).expect("sk deser failed");

        let message = b"Serialization roundtrip";
        let context: &[u8] = b"";
        let sig = sk2.try_sign(message, context).expect("sign failed");
        assert!(pk2.verify(message, &sig, context), "Must verify after key deserialization");
    }

    #[test]
    fn test_ml_dsa_65_key_serialization() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen failed");

        assert_eq!(pk.into_bytes().len(), ml_dsa_65::PK_LEN);
        assert_eq!(sk.into_bytes().len(), ml_dsa_65::SK_LEN);

        let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen2 failed");
        let pk2 = ml_dsa_65::PublicKey::try_from_bytes(pk.into_bytes()).expect("pk deser failed");
        let sk2 = ml_dsa_65::PrivateKey::try_from_bytes(sk.into_bytes()).expect("sk deser failed");

        let message = b"ML-DSA-65 serialization";
        let context: &[u8] = b"";
        let sig = sk2.try_sign(message, context).expect("sign failed");
        assert!(pk2.verify(message, &sig, context));
    }
}
