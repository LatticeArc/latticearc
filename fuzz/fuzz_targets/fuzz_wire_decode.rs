#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the binary wire-format v1 decoders.
//!
//! Every `from_wire` must be total (no panic, no allocation beyond the input)
//! and canonical: a successful decode re-encodes to the identical bytes. The
//! first input byte optionally selects a type so that a valid header is
//! prepended, letting the fuzzer reach the body parsers quickly.

use latticearc::hybrid::wire::{WIRE_MAGIC, WIRE_VERSION};
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

fn check_all(data: &[u8]) {
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
