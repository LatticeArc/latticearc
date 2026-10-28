//! Known-answer vectors for the segmented AEAD (`primitives::aead::segmented`).
//!
//! `fixtures/segmented-v1.json` is produced by
//! `scripts/generate-segmented-fixtures.py`, an independent Python
//! HKDF-SHA256/AES-256-GCM reference implementation that does not call
//! LatticeArc. Every record must seal to exactly the stored SHA-256 and open
//! back to the same plaintext. The labels are passed as test data.
#![cfg(feature = "kat-test-vectors")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeMap;

use latticearc::primitives::aead::aes_gcm::AesGcm256;
use latticearc::primitives::aead::segmented::{
    PAYLOAD_LEN, RECORD_LEN, SegmentedContext, SegmentedDecryptor, SegmentedEncryptor,
    SegmentedLabels, derive_object_id,
};
use latticearc::primitives::aead::{AeadCipher, Nonce};
use latticearc::primitives::hash::sha2::sha256;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    record_len: usize,
    payload_len: usize,
    record_key_label_hex: String,
    record_aad_label_hex: String,
    object_id_prefix_hex: String,
    secret_hex: String,
    generation_hex: String,
    nonce_hex: String,
    locator_hex: String,
    object_id_hex: String,
    bindings: BTreeMap<String, String>,
    cases: Vec<Case>,
    detail: Detail,
    negatives: Vec<Negative>,
}

#[derive(Deserialize)]
struct Case {
    binding: String,
    length: u64,
    records: u64,
    record_sha256: Vec<String>,
    stream_sha256: String,
}

#[derive(Deserialize)]
struct Detail {
    binding: String,
    length: u64,
    index: u64,
    record_key_hex: String,
    aad_hex: String,
}

#[derive(Deserialize)]
struct Negative {
    name: String,
    binding: String,
    length: u64,
    index: u64,
    record_sha256: String,
}

struct Inputs {
    fixtures: Fixtures,
    key_label: Vec<u8>,
    aad_label: Vec<u8>,
    secret: [u8; 32],
    generation: [u8; 32],
    nonce: Nonce,
    object_id: [u8; 32],
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn inputs() -> Inputs {
    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/segmented-v1.json")).unwrap();
    Inputs {
        key_label: unhex(&fixtures.record_key_label_hex),
        aad_label: unhex(&fixtures.record_aad_label_hex),
        secret: unhex(&fixtures.secret_hex).try_into().unwrap(),
        generation: unhex(&fixtures.generation_hex).try_into().unwrap(),
        nonce: unhex(&fixtures.nonce_hex).try_into().unwrap(),
        object_id: unhex(&fixtures.object_id_hex).try_into().unwrap(),
        fixtures,
    }
}

impl Inputs {
    fn context(&self, binding: &str, length: u64) -> SegmentedContext {
        let binding = unhex(&self.fixtures.bindings[binding]);
        let labels = SegmentedLabels { record_key: &self.key_label, record_aad: &self.aad_label };
        SegmentedContext::new(labels, &binding, self.object_id, self.generation, length).unwrap()
    }
}

fn plaintext(start: u64, end: u64) -> Vec<u8> {
    (start..end).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

#[test]
fn segmented_kat_geometry_matches_fixture() {
    let v = inputs();
    assert_eq!(v.fixtures.record_len, RECORD_LEN);
    assert_eq!(v.fixtures.payload_len, PAYLOAD_LEN);
    for case in &v.fixtures.cases {
        let context = v.context(&case.binding, case.length);
        assert_eq!(context.record_count(), case.records);
        assert_eq!(context.ciphertext_len(), case.records * RECORD_LEN as u64);
    }
}

#[test]
fn segmented_kat_object_id_matches_fixture() {
    let v = inputs();
    let id =
        derive_object_id(&unhex(&v.fixtures.object_id_prefix_hex), &unhex(&v.fixtures.locator_hex))
            .unwrap();
    assert_eq!(id, v.object_id);
}

#[test]
fn segmented_kat_record_key_and_aad_match_fixture() {
    let v = inputs();
    let d = &v.fixtures.detail;
    let context = v.context(&d.binding, d.length);
    assert_eq!(context.record_aad(d.index).unwrap(), unhex(&d.aad_hex));
    assert_eq!(
        context.record_key(&v.secret, d.index).unwrap().as_slice(),
        unhex(&d.record_key_hex)
    );
}

#[test]
fn segmented_kat_records_seal_and_open_byte_for_byte() {
    let v = inputs();
    for case in &v.fixtures.cases {
        let context = v.context(&case.binding, case.length);
        let mut encryptor = SegmentedEncryptor::new(&v.secret, context.clone()).unwrap();
        let mut decryptor = SegmentedDecryptor::new(&v.secret, context).unwrap();
        let mut stream = Vec::new();
        for (index, expected) in (0u64..).zip(&case.record_sha256) {
            let start = index * PAYLOAD_LEN as u64;
            let chunk = plaintext(start, (start + PAYLOAD_LEN as u64).min(case.length));
            let record = encryptor.seal_next_with_nonce(&chunk, &v.nonce).unwrap();
            assert_eq!(record.len(), RECORD_LEN);
            assert_eq!(
                hex::encode(sha256(&record).unwrap()),
                *expected,
                "length {} record {index}",
                case.length
            );
            assert_eq!(decryptor.open_next(&record).unwrap().as_slice(), chunk.as_slice());
            stream.extend_from_slice(&record);
        }
        encryptor.finish().unwrap();
        decryptor.finish().unwrap();
        assert_eq!(hex::encode(sha256(&stream).unwrap()), case.stream_sha256);
    }
}

#[test]
fn segmented_kat_authenticated_negatives_are_rejected() {
    let v = inputs();
    for negative in &v.fixtures.negatives {
        let context = v.context(&negative.binding, negative.length);
        let key = context.record_key(&v.secret, negative.index).unwrap();
        let mut aad = context.record_aad(negative.index).unwrap();
        let mut padded = vec![0u8; PAYLOAD_LEN];
        let payload = plaintext(0, negative.length);
        padded[..payload.len()].copy_from_slice(&payload);
        match negative.name.as_str() {
            "nonzero_padding" => padded[payload.len()] = 1,
            "final_flag_cleared" => *aad.last_mut().unwrap() = 0,
            other => panic!("unknown negative vector {other}"),
        }
        let (ciphertext, tag) =
            AesGcm256::new(key.as_slice()).unwrap().encrypt(&v.nonce, &padded, Some(&aad)).unwrap();
        let record = [v.nonce.as_slice(), &ciphertext, &tag].concat();
        assert_eq!(
            hex::encode(sha256(&record).unwrap()),
            negative.record_sha256,
            "{}",
            negative.name
        );
        let mut decryptor = SegmentedDecryptor::new(&v.secret, context).unwrap();
        assert!(decryptor.open_next(&record).is_err(), "{}", negative.name);
        assert!(decryptor.finish().is_err(), "{}", negative.name);
    }
}
