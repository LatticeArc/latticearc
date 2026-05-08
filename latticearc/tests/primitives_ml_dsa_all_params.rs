//! Coverage tests for ML-DSA sign/verify with all parameter sets (44, 65, 87)
//! Exercises code paths in arc-primitives/src/sig/ml_dsa.rs that require
//! different parameter set variants.

#![allow(clippy::unwrap_used, clippy::panic)]

use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

const TEST_MESSAGE: &[u8] = b"Test message for ML-DSA coverage";
const TEST_CONTEXT: &[u8] = b"";

#[test]
fn test_ml_dsa_44_sign_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).unwrap();
    let sig = sk.sign(TEST_MESSAGE, TEST_CONTEXT).unwrap();
    assert_eq!(sig.parameter_set(), MlDsaParameterSet::MlDsa44);
    let valid = pk.verify(TEST_MESSAGE, &sig, TEST_CONTEXT).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_65_sign_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
    let sig = sk.sign(TEST_MESSAGE, TEST_CONTEXT).unwrap();
    assert_eq!(sig.parameter_set(), MlDsaParameterSet::MlDsa65);
    let valid = pk.verify(TEST_MESSAGE, &sig, TEST_CONTEXT).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_87_sign_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).unwrap();
    let sig = sk.sign(TEST_MESSAGE, TEST_CONTEXT).unwrap();
    assert_eq!(sig.parameter_set(), MlDsaParameterSet::MlDsa87);
    let valid = pk.verify(TEST_MESSAGE, &sig, TEST_CONTEXT).unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_wrong_message_fails_all_params_fails() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (pk, sk) = generate_keypair(param).unwrap();
        let sig = sk.sign(TEST_MESSAGE, TEST_CONTEXT).unwrap();
        let valid = pk.verify(b"Wrong message", &sig, TEST_CONTEXT).unwrap();
        assert!(!valid, "Wrong message should fail for {:?}", param);
    }
}

#[test]
fn test_ml_dsa_parameter_set_mismatch_fails() {
    use latticearc::primitives::sig::ml_dsa::MlDsaError;

    let (pk44, _sk44) = generate_keypair(MlDsaParameterSet::MlDsa44).unwrap();
    let (_pk65, sk65) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
    let sig65 = sk65.sign(TEST_MESSAGE, TEST_CONTEXT).unwrap();

    // verify() returns Err(ParameterSetMismatch) on
    // mismatch instead of Ok(false). Configuration errors no longer
    // masquerade as forgeries — callers branching on Ok(false) for
    // "invalid signature" cannot conflate the two.
    let result = pk44.verify(TEST_MESSAGE, &sig65, TEST_CONTEXT);
    match result {
        Err(MlDsaError::ParameterSetMismatch { key, signature }) => {
            assert_eq!(key, MlDsaParameterSet::MlDsa44);
            assert_eq!(signature, MlDsaParameterSet::MlDsa65);
        }
        other => panic!("expected ParameterSetMismatch, got {other:?}"),
    }
}

#[test]
fn test_ml_dsa_key_sizes_has_correct_size() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (pk, sk) = generate_keypair(param).unwrap();
        assert_eq!(pk.len(), param.public_key_size());
        assert_eq!(sk.len(), param.secret_key_size());

        let sig = sk.sign(TEST_MESSAGE, TEST_CONTEXT).unwrap();
        assert_eq!(sig.len(), param.signature_size());
    }
}

#[test]
fn test_ml_dsa_parameter_set_properties_succeeds() {
    let p44 = MlDsaParameterSet::MlDsa44;
    assert_eq!(p44.nist_security_level(), 2);
    assert_eq!(p44.public_key_size(), 1312);
    assert_eq!(p44.secret_key_size(), 2560);
    assert_eq!(p44.signature_size(), 2420);

    let p65 = MlDsaParameterSet::MlDsa65;
    assert_eq!(p65.nist_security_level(), 3);
    assert_eq!(p65.public_key_size(), 1952);
    assert_eq!(p65.secret_key_size(), 4032);
    assert_eq!(p65.signature_size(), 3309);

    let p87 = MlDsaParameterSet::MlDsa87;
    assert_eq!(p87.nist_security_level(), 5);
    assert_eq!(p87.public_key_size(), 2592);
    assert_eq!(p87.secret_key_size(), 4896);
    assert_eq!(p87.signature_size(), 4627);
}

#[test]
fn test_ml_dsa_empty_and_large_messages_succeeds() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (pk, sk) = generate_keypair(param).unwrap();

        // Empty message
        let sig = sk.sign(b"", TEST_CONTEXT).unwrap();
        assert!(pk.verify(b"", &sig, TEST_CONTEXT).unwrap());

        // Large message
        let large = vec![0xABu8; 10000];
        let sig = sk.sign(&large, TEST_CONTEXT).unwrap();
        assert!(pk.verify(&large, &sig, TEST_CONTEXT).unwrap());
    }
}

#[test]
fn test_ml_dsa_with_context_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
    let context = b"custom-context-string";
    let sig = sk.sign(TEST_MESSAGE, context).unwrap();
    assert!(pk.verify(TEST_MESSAGE, &sig, context).unwrap());

    // Wrong context should fail
    let wrong_context = b"wrong-context";
    let valid = pk.verify(TEST_MESSAGE, &sig, wrong_context).unwrap();
    assert!(!valid, "Wrong context should fail verification");
}
