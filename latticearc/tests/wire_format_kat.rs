//! Known-answer vectors for the binary wire format v1 (`docs/WIRE_FORMAT.md`).
//!
//! `fixtures/wire-v1.json` is produced by `scripts/generate-wire-fixtures.py`,
//! an implementation of the documented layout that does not call LatticeArc.
//! Each vector must encode to exactly the stored bytes and decode back to the
//! same components on every platform, catching layout or endianness drift.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use latticearc::hybrid::wire::{WIRE_HEADER_LEN, WIRE_MAGIC, WIRE_VERSION};
use latticearc::primitives::kem::MlKemSecurityLevel;
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc::{
    EncapsulatedKey, HybridCiphertext, HybridKemPublicKey, HybridSigPublicKey, HybridSignature,
    WireEncode,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    type_tag: u8,
    algorithm_id: u8,
    fields: Vec<Field>,
    wire_hex: String,
}

#[derive(Deserialize)]
struct Field {
    name: String,
    len: usize,
    seed: u8,
}

fn fixtures() -> Fixtures {
    serde_json::from_str(include_str!("fixtures/wire-v1.json")).unwrap()
}

/// Same filler as the generator: `b = b * 29 + 7 (mod 256)`, emit each `b`.
fn filled(len: usize, seed: u8) -> Vec<u8> {
    let mut b = seed;
    (0..len)
        .map(|_| {
            b = b.wrapping_mul(29).wrapping_add(7);
            b
        })
        .collect()
}

fn field(vector: &Vector, name: &str) -> Vec<u8> {
    let f = vector.fields.iter().find(|f| f.name == name).unwrap();
    filled(f.len, f.seed)
}

fn kem_level(id: u8) -> MlKemSecurityLevel {
    match id {
        1 => MlKemSecurityLevel::MlKem512,
        3 => MlKemSecurityLevel::MlKem768,
        5 => MlKemSecurityLevel::MlKem1024,
        other => panic!("unexpected ML-KEM id {other}"),
    }
}

fn dsa_set(id: u8) -> MlDsaParameterSet {
    match id {
        2 => MlDsaParameterSet::MlDsa44,
        3 => MlDsaParameterSet::MlDsa65,
        5 => MlDsaParameterSet::MlDsa87,
        other => panic!("unexpected ML-DSA id {other}"),
    }
}

/// Encode the vector's components and decode the stored bytes; return the
/// re-encoding of the decoded value.
fn check_vector(v: &Vector, wire: &[u8]) -> Vec<u8> {
    match v.type_tag {
        0x01 => {
            let level = kem_level(v.algorithm_id);
            let pk = HybridKemPublicKey::new(field(v, "ml_kem_pk"), field(v, "ecdh_pk"), level);
            assert_eq!(pk.to_wire().unwrap(), wire, "{}: encode", v.name);
            let dec = HybridKemPublicKey::from_wire(wire).unwrap();
            assert_eq!(dec.security_level(), level);
            assert_eq!(dec.ml_kem_pk(), field(v, "ml_kem_pk").as_slice());
            assert_eq!(dec.ecdh_pk(), field(v, "ecdh_pk").as_slice());
            dec.to_wire().unwrap()
        }
        0x02 => {
            let ek = EncapsulatedKey::for_decapsulate(field(v, "ml_kem_ct"), field(v, "ecdh_pk"));
            assert_eq!(ek.to_wire().unwrap(), wire, "{}: encode", v.name);
            let dec = EncapsulatedKey::from_wire(wire).unwrap();
            assert_eq!(dec.ml_kem_ct(), field(v, "ml_kem_ct").as_slice());
            assert_eq!(dec.ecdh_pk(), field(v, "ecdh_pk").as_slice());
            dec.to_wire().unwrap()
        }
        0x03 => {
            let ct = HybridCiphertext::new(
                field(v, "kem_ciphertext"),
                field(v, "ecdh_ephemeral_pk"),
                field(v, "symmetric_ciphertext"),
                field(v, "nonce"),
                field(v, "tag"),
            );
            assert_eq!(ct.to_wire().unwrap(), wire, "{}: encode", v.name);
            let dec = HybridCiphertext::from_wire(wire).unwrap();
            assert_eq!(dec.kem_ciphertext(), field(v, "kem_ciphertext").as_slice());
            assert_eq!(dec.ecdh_ephemeral_pk(), field(v, "ecdh_ephemeral_pk").as_slice());
            assert_eq!(dec.symmetric_ciphertext(), field(v, "symmetric_ciphertext").as_slice());
            assert_eq!(dec.nonce(), field(v, "nonce").as_slice());
            assert_eq!(dec.tag(), field(v, "tag").as_slice());
            dec.to_wire().unwrap()
        }
        0x04 => {
            let set = dsa_set(v.algorithm_id);
            let pk = HybridSigPublicKey::new(set, field(v, "ml_dsa_pk"), field(v, "ed25519_pk"))
                .unwrap();
            assert_eq!(pk.to_wire().unwrap(), wire, "{}: encode", v.name);
            let dec = HybridSigPublicKey::from_wire(wire).unwrap();
            assert_eq!(dec.parameter_set(), set);
            assert_eq!(dec.ml_dsa_pk(), field(v, "ml_dsa_pk").as_slice());
            assert_eq!(dec.ed25519_pk(), field(v, "ed25519_pk").as_slice());
            dec.to_wire().unwrap()
        }
        0x05 => {
            let sig = HybridSignature::new(field(v, "ml_dsa_sig"), field(v, "ed25519_sig"));
            assert_eq!(sig.to_wire().unwrap(), wire, "{}: encode", v.name);
            let dec = HybridSignature::from_wire(wire).unwrap();
            assert_eq!(dec.ml_dsa_sig(), field(v, "ml_dsa_sig").as_slice());
            assert_eq!(dec.ed25519_sig(), field(v, "ed25519_sig").as_slice());
            dec.to_wire().unwrap()
        }
        other => panic!("{}: unexpected type tag {other}", v.name),
    }
}

#[test]
fn wire_kat_vectors_encode_and_decode_exactly() {
    let fixtures = fixtures();
    let mut seen = [0usize; 6];
    for v in &fixtures.vectors {
        let wire = hex::decode(&v.wire_hex).unwrap();
        assert_eq!(&wire[..2], &WIRE_MAGIC, "{}", v.name);
        assert_eq!(wire[2], WIRE_VERSION, "{}", v.name);
        assert_eq!(wire[3], v.type_tag, "{}", v.name);
        assert_eq!(wire[4], v.algorithm_id, "{}", v.name);
        assert!(wire.len() > WIRE_HEADER_LEN);
        assert_eq!(check_vector(v, &wire), wire, "{}: re-encode", v.name);
        seen[usize::from(v.type_tag)] += 1;
    }
    // Every type at every algorithm level.
    assert_eq!(seen, [0, 3, 3, 3, 3, 3]);
}
