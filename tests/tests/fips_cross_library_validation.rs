//! Cross-Library Validation Tests
//!
//! These tests validate interoperability between independent PQC implementations:
//! - `fips203` crate (pure Rust ML-KEM)
//! - `aws-lc-rs` (C/ASM ML-KEM via AWS-LC)
//!
//! This catches encoding differences, parameter mismatches, or wrapping bugs
//! that NIST KAT vectors alone cannot detect (since KATs test one implementation
//! at a time).
//!
//! ## What This Validates
//!
//! 1. Key format compatibility: keys from one library work in the other
//! 2. Encapsulation/decapsulation cross-library: encapsulate with lib A, decapsulate with lib B
//! 3. Shared secret agreement: both libraries produce the same shared secret
//! 4. Key size consistency: both libraries agree on FIPS 203 parameter sizes

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aws_lc_rs::kem::{DecapsulationKey, EncapsulationKey, ML_KEM_768};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// Test that fips203 and aws-lc-rs agree on ML-KEM-768 public key size
#[test]
fn test_ml_kem_768_key_size_agreement() {
    // fips203: generate keypair
    let (ek_fips, _dk_fips) =
        <ml_kem_768::KG as KeyGen>::try_keygen().expect("fips203 keygen should succeed");
    let pk_fips_bytes = ek_fips.into_bytes();

    // aws-lc-rs: generate keypair
    let dk_aws = DecapsulationKey::generate(&ML_KEM_768).expect("aws-lc-rs keygen should succeed");
    let ek_aws = dk_aws.encapsulation_key().expect("aws-lc-rs encaps key should succeed");
    let pk_aws_bytes = ek_aws.key_bytes().expect("aws-lc-rs key bytes should succeed");

    // FIPS 203 Table 2: ML-KEM-768 public key is 1184 bytes
    assert_eq!(pk_fips_bytes.len(), 1184, "fips203 ML-KEM-768 public key should be 1184 bytes");
    assert_eq!(
        pk_aws_bytes.as_ref().len(),
        1184,
        "aws-lc-rs ML-KEM-768 public key should be 1184 bytes"
    );
}

/// Test cross-library encapsulation: fips203 key → aws-lc-rs encapsulate → fips203 decapsulate
#[test]
fn test_cross_library_fips203_keygen_aws_encaps() {
    // Step 1: Generate keypair with fips203
    let (ek_fips, dk_fips) =
        <ml_kem_768::KG as KeyGen>::try_keygen().expect("fips203 keygen should succeed");
    let pk_bytes = ek_fips.into_bytes();

    // Step 2: Import public key into aws-lc-rs and encapsulate
    let ek_aws = EncapsulationKey::new(&ML_KEM_768, &pk_bytes)
        .expect("aws-lc-rs should accept fips203 public key");
    let (ct_aws, ss_aws) = ek_aws.encapsulate().expect("aws-lc-rs encapsulate should succeed");

    // Step 3: Decapsulate with fips203
    let ct_bytes = ct_aws.as_ref();
    let ct_fips = ml_kem_768::CipherText::try_from_bytes(ct_bytes.try_into().expect("ct size"))
        .expect("fips203 should accept aws-lc-rs ciphertext");
    let ss_fips = dk_fips.try_decaps(&ct_fips).expect("fips203 decapsulate should succeed");

    // Step 4: Verify shared secrets match
    let ss_fips_bytes = ss_fips.into_bytes();
    assert_eq!(
        ss_fips_bytes.as_ref(),
        ss_aws.as_ref(),
        "Shared secrets must match across fips203 (decaps) and aws-lc-rs (encaps)"
    );
}

/// Test cross-library encapsulation: aws-lc-rs key → fips203 encapsulate → aws-lc-rs decapsulate
#[test]
fn test_cross_library_aws_keygen_fips203_encaps() {
    // Step 1: Generate keypair with aws-lc-rs
    let dk_aws = DecapsulationKey::generate(&ML_KEM_768).expect("aws-lc-rs keygen should succeed");
    let ek_aws = dk_aws.encapsulation_key().expect("aws-lc-rs encaps key should succeed");
    let pk_bytes = ek_aws.key_bytes().expect("aws-lc-rs key bytes should succeed");

    // Step 2: Import public key into fips203 and encapsulate
    let pk_array: &[u8; 1184] =
        pk_bytes.as_ref().try_into().expect("aws-lc-rs pk should be 1184 bytes");
    let ek_fips = ml_kem_768::EncapsKey::try_from_bytes(*pk_array)
        .expect("fips203 should accept aws-lc-rs public key");
    let (ss_fips, ct_fips) = ek_fips.try_encaps().expect("fips203 encapsulate should succeed");

    // Step 3: Decapsulate with aws-lc-rs
    let ct_bytes = ct_fips.into_bytes();
    let ss_aws =
        dk_aws.decapsulate(ct_bytes.as_ref().into()).expect("aws-lc-rs decapsulate should succeed");

    // Step 4: Verify shared secrets match
    let ss_fips_bytes = ss_fips.into_bytes();
    assert_eq!(
        ss_fips_bytes.as_ref(),
        ss_aws.as_ref(),
        "Shared secrets must match across aws-lc-rs (decaps) and fips203 (encaps)"
    );
}

/// Test that multiple cross-library roundtrips all produce valid shared secrets
#[test]
fn test_cross_library_roundtrip_consistency() {
    for i in 0..5 {
        // Alternate which library generates the key
        if i % 2 == 0 {
            // fips203 keygen → aws-lc-rs encaps → fips203 decaps
            let (ek, dk) =
                <ml_kem_768::KG as KeyGen>::try_keygen().expect("fips203 keygen should succeed");
            let pk_bytes = ek.into_bytes();

            let ek_aws = EncapsulationKey::new(&ML_KEM_768, &pk_bytes)
                .expect("aws-lc-rs should accept fips203 public key");
            let (ct, ss_encaps) =
                ek_aws.encapsulate().expect("aws-lc-rs encapsulate should succeed");

            let ct_arr: &[u8; 1088] = ct.as_ref().try_into().expect("ct size");
            let ct_fips = ml_kem_768::CipherText::try_from_bytes(*ct_arr).expect("ct from bytes");
            let ss_decaps = dk.try_decaps(&ct_fips).expect("fips203 decaps should succeed");

            assert_eq!(
                ss_decaps.into_bytes().as_ref(),
                ss_encaps.as_ref(),
                "Roundtrip {} failed (fips203 key)",
                i
            );
        } else {
            // aws-lc-rs keygen → fips203 encaps → aws-lc-rs decaps
            let dk =
                DecapsulationKey::generate(&ML_KEM_768).expect("aws-lc-rs keygen should succeed");
            let ek = dk.encapsulation_key().expect("encaps key");
            let pk_bytes = ek.key_bytes().expect("key bytes");

            let pk_arr: &[u8; 1184] = pk_bytes.as_ref().try_into().expect("pk size");
            let ek_fips =
                ml_kem_768::EncapsKey::try_from_bytes(*pk_arr).expect("fips203 from bytes");
            let (ss_encaps, ct) = ek_fips.try_encaps().expect("fips203 encaps should succeed");

            let ct_bytes = ct.into_bytes();
            let ss_decaps =
                dk.decapsulate(ct_bytes.as_ref().into()).expect("aws-lc-rs decaps should succeed");

            assert_eq!(
                ss_encaps.into_bytes().as_ref(),
                ss_decaps.as_ref(),
                "Roundtrip {} failed (aws-lc-rs key)",
                i
            );
        }
    }
}
