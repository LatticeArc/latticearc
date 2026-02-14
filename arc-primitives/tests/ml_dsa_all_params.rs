//! Coverage tests for ML-DSA sign/verify with all parameter sets (44, 65, 87)
//! Exercises code paths in arc-primitives/src/sig/ml_dsa.rs that require
//! different parameter set variants.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};

const TEST_MESSAGE: &[u8] = b"Test message for ML-DSA coverage";
const TEST_CONTEXT: &[u8] = b"";

#[test]
fn test_ml_dsa_44_sign_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let sig = sign(&sk, TEST_MESSAGE, TEST_CONTEXT).unwrap();
    assert_eq!(sig.parameter_set, MlDsaParameterSet::MLDSA44);
    let valid = verify(&pk, TEST_MESSAGE, &sig, TEST_CONTEXT).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_65_sign_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    let sig = sign(&sk, TEST_MESSAGE, TEST_CONTEXT).unwrap();
    assert_eq!(sig.parameter_set, MlDsaParameterSet::MLDSA65);
    let valid = verify(&pk, TEST_MESSAGE, &sig, TEST_CONTEXT).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_87_sign_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).unwrap();
    let sig = sign(&sk, TEST_MESSAGE, TEST_CONTEXT).unwrap();
    assert_eq!(sig.parameter_set, MlDsaParameterSet::MLDSA87);
    let valid = verify(&pk, TEST_MESSAGE, &sig, TEST_CONTEXT).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_wrong_message_fails_all_params() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = generate_keypair(param).unwrap();
        let sig = sign(&sk, TEST_MESSAGE, TEST_CONTEXT).unwrap();
        let valid = verify(&pk, b"Wrong message", &sig, TEST_CONTEXT).unwrap();
        assert!(!valid, "Wrong message should fail for {:?}", param);
    }
}

#[test]
fn test_ml_dsa_parameter_set_mismatch() {
    let (pk44, _sk44) = generate_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let (_pk65, sk65) = generate_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    let sig65 = sign(&sk65, TEST_MESSAGE, TEST_CONTEXT).unwrap();

    // Verify with mismatched parameter sets should return Ok(false)
    let result = verify(&pk44, TEST_MESSAGE, &sig65, TEST_CONTEXT).unwrap();
    assert!(!result, "Mismatched parameter sets should return false");
}

#[test]
fn test_ml_dsa_key_sizes() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = generate_keypair(param).unwrap();
        assert_eq!(pk.len(), param.public_key_size());
        assert_eq!(sk.len(), param.secret_key_size());

        let sig = sign(&sk, TEST_MESSAGE, TEST_CONTEXT).unwrap();
        assert_eq!(sig.len(), param.signature_size());
    }
}

#[test]
fn test_ml_dsa_parameter_set_properties() {
    let p44 = MlDsaParameterSet::MLDSA44;
    assert_eq!(p44.nist_security_level(), 2);
    assert_eq!(p44.public_key_size(), 1312);
    assert_eq!(p44.secret_key_size(), 2560);
    assert_eq!(p44.signature_size(), 2420);

    let p65 = MlDsaParameterSet::MLDSA65;
    assert_eq!(p65.nist_security_level(), 3);
    assert_eq!(p65.public_key_size(), 1952);
    assert_eq!(p65.secret_key_size(), 4032);
    assert_eq!(p65.signature_size(), 3309);

    let p87 = MlDsaParameterSet::MLDSA87;
    assert_eq!(p87.nist_security_level(), 5);
    assert_eq!(p87.public_key_size(), 2592);
    assert_eq!(p87.secret_key_size(), 4896);
    assert_eq!(p87.signature_size(), 4627);
}

#[test]
fn test_ml_dsa_empty_and_large_messages() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = generate_keypair(param).unwrap();

        // Empty message
        let sig = sign(&sk, b"", TEST_CONTEXT).unwrap();
        assert!(verify(&pk, b"", &sig, TEST_CONTEXT).unwrap());

        // Large message
        let large = vec![0xABu8; 10000];
        let sig = sign(&sk, &large, TEST_CONTEXT).unwrap();
        assert!(verify(&pk, &large, &sig, TEST_CONTEXT).unwrap());
    }
}

#[test]
fn test_ml_dsa_with_context() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    let context = b"custom-context-string";
    let sig = sign(&sk, TEST_MESSAGE, context).unwrap();
    assert!(verify(&pk, TEST_MESSAGE, &sig, context).unwrap());

    // Wrong context should fail
    let wrong_context = b"wrong-context";
    let valid = verify(&pk, TEST_MESSAGE, &sig, wrong_context).unwrap();
    assert!(!valid, "Wrong context should fail verification");
}
