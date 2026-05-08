//! Cross-implementation stress testing for ML-KEM (FIPS 203).
//!
//! The deterministic cross-library tests in `fips_cross_validation.rs`
//! cover ML-KEM-768 only, with a handful of one-shot comparisons. This
//! file extends that coverage to:
//!
//! - All three parameter sets (ML-KEM-512 / 768 / 1024).
//! - `ITERATIONS` random round-trips per direction per level — so every
//!   test run exercises hundreds of independently-generated keypairs
//!   and ciphertexts through *both* implementations, catching any rare
//!   disagreement that a single-shot deterministic test cannot.
//!
//! Cross-library contract: if `fips203` (pure-Rust reference, NIST
//! per-spec) and `aws-lc-rs` (C/asm, FIPS-validated) both implement
//! FIPS 203, they must agree on shared-secret derivation from the same
//! public key / ciphertext pair. Any divergence is a library bug on
//! one side and would break interop.
//!
//! Mirrors `cross_impl_ml_dsa.rs` and `cross_impl_slh_dsa.rs` landed
//! in Phase 2a (commit 69005c5f); completes the cross-impl matrix for
//! the three NIST PQC primitives we ship.

#![allow(clippy::expect_used)]

use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_512, ML_KEM_768, ML_KEM_1024};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::{ml_kem_512, ml_kem_768, ml_kem_1024};

/// Number of round-trips per test. 100 is enough to catch any
/// reproducible divergence without inflating test wall-clock
/// substantially — one round-trip is ~1 ms per impl.
const ITERATIONS: usize = 100;

// =============================================================================
// Direction A: fips203 keygen + encaps → aws-lc-rs decaps
// =============================================================================

fn fips_encaps_aws_decaps_512_iter() {
    let (ek_fips, dk_fips) = <ml_kem_512::KG as KeyGen>::try_keygen().expect("fips203-512 keygen");
    let dk_bytes = dk_fips.into_bytes();

    let (ss_fips, ct_fips) = ek_fips.try_encaps().expect("fips203 encaps");
    let ct_bytes = ct_fips.into_bytes();

    let dk_aws = DecapsulationKey::new(&ML_KEM_512, &dk_bytes).expect("aws dk from bytes");
    let ss_aws = dk_aws.decapsulate(ct_bytes.as_slice().into()).expect("aws decaps");

    assert_eq!(ss_fips.into_bytes(), ss_aws.as_ref(), "ML-KEM-512 ss mismatch");
}

fn fips_encaps_aws_decaps_768_iter() {
    let (ek_fips, dk_fips) = <ml_kem_768::KG as KeyGen>::try_keygen().expect("fips203-768 keygen");
    let dk_bytes = dk_fips.into_bytes();

    let (ss_fips, ct_fips) = ek_fips.try_encaps().expect("fips203 encaps");
    let ct_bytes = ct_fips.into_bytes();

    let dk_aws = DecapsulationKey::new(&ML_KEM_768, &dk_bytes).expect("aws dk from bytes");
    let ss_aws = dk_aws.decapsulate(ct_bytes.as_slice().into()).expect("aws decaps");

    assert_eq!(ss_fips.into_bytes(), ss_aws.as_ref(), "ML-KEM-768 ss mismatch");
}

fn fips_encaps_aws_decaps_1024_iter() {
    let (ek_fips, dk_fips) =
        <ml_kem_1024::KG as KeyGen>::try_keygen().expect("fips203-1024 keygen");
    let dk_bytes = dk_fips.into_bytes();

    let (ss_fips, ct_fips) = ek_fips.try_encaps().expect("fips203 encaps");
    let ct_bytes = ct_fips.into_bytes();

    let dk_aws = DecapsulationKey::new(&ML_KEM_1024, &dk_bytes).expect("aws dk from bytes");
    let ss_aws = dk_aws.decapsulate(ct_bytes.as_slice().into()).expect("aws decaps");

    assert_eq!(ss_fips.into_bytes(), ss_aws.as_ref(), "ML-KEM-1024 ss mismatch");
}

#[test]
fn ml_kem_512_fips_encaps_aws_decaps_stress_agrees() {
    for _ in 0..ITERATIONS {
        fips_encaps_aws_decaps_512_iter();
    }
}

#[test]
fn ml_kem_768_fips_encaps_aws_decaps_stress_agrees() {
    for _ in 0..ITERATIONS {
        fips_encaps_aws_decaps_768_iter();
    }
}

#[test]
fn ml_kem_1024_fips_encaps_aws_decaps_stress_agrees() {
    for _ in 0..ITERATIONS {
        fips_encaps_aws_decaps_1024_iter();
    }
}

// =============================================================================
// Direction B: aws-lc-rs keygen + encaps → fips203 decaps
// =============================================================================

fn aws_encaps_fips_decaps_512_iter() {
    let dk_aws = DecapsulationKey::generate(&ML_KEM_512).expect("aws keygen");
    let ek_aws = dk_aws.encapsulation_key().expect("ek extract");
    let (ct_aws, ss_aws) = ek_aws.encapsulate().expect("aws encaps");
    let dk_bytes = dk_aws.key_bytes().expect("dk bytes");

    let dk_fips =
        ml_kem_512::DecapsKey::try_from_bytes(dk_bytes.as_ref().try_into().expect("dk-512 length"))
            .expect("fips dk from bytes");
    let ct_fips =
        ml_kem_512::CipherText::try_from_bytes(ct_aws.as_ref().try_into().expect("ct-512 length"))
            .expect("fips ct from bytes");
    let ss_fips = dk_fips.try_decaps(&ct_fips).expect("fips decaps");

    assert_eq!(ss_aws.as_ref(), &ss_fips.into_bytes(), "ML-KEM-512 ss mismatch");
}

fn aws_encaps_fips_decaps_768_iter() {
    let dk_aws = DecapsulationKey::generate(&ML_KEM_768).expect("aws keygen");
    let ek_aws = dk_aws.encapsulation_key().expect("ek extract");
    let (ct_aws, ss_aws) = ek_aws.encapsulate().expect("aws encaps");
    let dk_bytes = dk_aws.key_bytes().expect("dk bytes");

    let dk_fips =
        ml_kem_768::DecapsKey::try_from_bytes(dk_bytes.as_ref().try_into().expect("dk-768 length"))
            .expect("fips dk from bytes");
    let ct_fips =
        ml_kem_768::CipherText::try_from_bytes(ct_aws.as_ref().try_into().expect("ct-768 length"))
            .expect("fips ct from bytes");
    let ss_fips = dk_fips.try_decaps(&ct_fips).expect("fips decaps");

    assert_eq!(ss_aws.as_ref(), &ss_fips.into_bytes(), "ML-KEM-768 ss mismatch");
}

fn aws_encaps_fips_decaps_1024_iter() {
    let dk_aws = DecapsulationKey::generate(&ML_KEM_1024).expect("aws keygen");
    let ek_aws = dk_aws.encapsulation_key().expect("ek extract");
    let (ct_aws, ss_aws) = ek_aws.encapsulate().expect("aws encaps");
    let dk_bytes = dk_aws.key_bytes().expect("dk bytes");

    let dk_fips = ml_kem_1024::DecapsKey::try_from_bytes(
        dk_bytes.as_ref().try_into().expect("dk-1024 length"),
    )
    .expect("fips dk from bytes");
    let ct_fips = ml_kem_1024::CipherText::try_from_bytes(
        ct_aws.as_ref().try_into().expect("ct-1024 length"),
    )
    .expect("fips ct from bytes");
    let ss_fips = dk_fips.try_decaps(&ct_fips).expect("fips decaps");

    assert_eq!(ss_aws.as_ref(), &ss_fips.into_bytes(), "ML-KEM-1024 ss mismatch");
}

#[test]
fn ml_kem_512_aws_encaps_fips_decaps_stress_agrees() {
    for _ in 0..ITERATIONS {
        aws_encaps_fips_decaps_512_iter();
    }
}

#[test]
fn ml_kem_768_aws_encaps_fips_decaps_stress_agrees() {
    for _ in 0..ITERATIONS {
        aws_encaps_fips_decaps_768_iter();
    }
}

#[test]
fn ml_kem_1024_aws_encaps_fips_decaps_stress_agrees() {
    for _ in 0..ITERATIONS {
        aws_encaps_fips_decaps_1024_iter();
    }
}
