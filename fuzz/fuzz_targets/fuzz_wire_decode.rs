#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the binary wire-format v1 decoders.
//!
//! Every `from_wire` must be total (no panic, no allocation beyond the input)
//! and canonical: a successful decode re-encodes to the identical bytes. The
//! first input byte optionally selects a type so that a valid header is
//! prepended, letting the fuzzer reach the body parsers quickly.
//!
//! The level-pinned public-key decoders (`from_wire_with_policy`) must agree
//! with `from_wire`: they succeed exactly when `from_wire` succeeds with an
//! allowed level, and then yield the same value.

use latticearc::hybrid::wire::{WIRE_MAGIC, WIRE_VERSION};
use latticearc::primitives::kem::MlKemSecurityLevel;
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc::{
    EncapsulatedKey, HybridCiphertext, HybridKemPublicKey, HybridSigPublicKey, HybridSignature,
    WireEncode,
};
use libfuzzer_sys::fuzz_target;

fn check<T: WireEncode>(data: &[u8]) {
    if let Ok(value) = T::from_wire(data) {
        let encoded = value.to_wire().expect("decoded value must re-encode");
        assert_eq!(encoded, data, "wire encoding must be canonical");
    }
}

fn check_level_pinned(data: &[u8]) {
    let kem_allowed = [MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024];
    let kem_plain = HybridKemPublicKey::from_wire(data);
    let kem_pinned = HybridKemPublicKey::from_wire_with_policy(data, &kem_allowed);
    match (&kem_plain, &kem_pinned) {
        (Ok(plain), Ok(pinned)) => {
            assert!(kem_allowed.contains(&plain.security_level()));
            assert_eq!(plain.to_wire().unwrap(), pinned.to_wire().unwrap());
        }
        (Ok(plain), Err(_)) => assert!(!kem_allowed.contains(&plain.security_level())),
        (Err(_), Ok(_)) => panic!("pinned KEM decode accepted what from_wire rejects"),
        (Err(_), Err(_)) => {}
    }
    assert!(HybridKemPublicKey::from_wire_with_policy(data, &[]).is_err());

    let dsa_allowed = [MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87];
    let sig_plain = HybridSigPublicKey::from_wire(data);
    let sig_pinned = HybridSigPublicKey::from_wire_with_policy(data, &dsa_allowed);
    match (&sig_plain, &sig_pinned) {
        (Ok(plain), Ok(pinned)) => {
            assert!(dsa_allowed.contains(&plain.parameter_set()));
            assert_eq!(plain.to_wire().unwrap(), pinned.to_wire().unwrap());
        }
        (Ok(plain), Err(_)) => assert!(!dsa_allowed.contains(&plain.parameter_set())),
        (Err(_), Ok(_)) => panic!("pinned signature-key decode accepted what from_wire rejects"),
        (Err(_), Err(_)) => {}
    }
    assert!(HybridSigPublicKey::from_wire_with_policy(data, &[]).is_err());
}

fn check_all(data: &[u8]) {
    check_level_pinned(data);
    check::<HybridKemPublicKey>(data);
    check::<EncapsulatedKey>(data);
    check::<HybridCiphertext>(data);
    check::<HybridSigPublicKey>(data);
    check::<HybridSignature>(data);
}

fuzz_target!(|data: &[u8]| {
    // Raw input: exercises magic / version / type / size checks.
    check_all(data);

    // Structured input: [selector][alg id][body...] with a valid header.
    if let [selector, alg_id, body @ ..] = data {
        let type_tag = (selector % 6) + 1;
        let mut framed = Vec::with_capacity(5 + body.len());
        framed.extend_from_slice(&WIRE_MAGIC);
        framed.push(WIRE_VERSION);
        framed.push(type_tag);
        framed.push(*alg_id);
        framed.extend_from_slice(body);
        check_all(&framed);
    }
});
