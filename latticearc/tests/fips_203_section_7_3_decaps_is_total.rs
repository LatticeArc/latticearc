//! FIPS 203 §7.3 conformance: `ML-KEM.Decaps` is a **total function**.
//!
//! NIST FIPS 203 (final, August 2024), §7.3 ML-KEM.Decaps mandates that the
//! decapsulation algorithm is **total over the space of correctly-sized
//! ciphertext byte strings**: it never returns an error or failure symbol.
//! Invalid (correctly-sized but tampered) ciphertexts MUST yield a
//! deterministic implicit-rejection shared secret derived from the secret key
//! and the ciphertext, so an adversary cannot distinguish a malformed
//! ciphertext from a well-formed one by error behaviour. This is the
//! IND-CCA2-securing property of the Fujisaki–Okamoto transform applied to
//! K-PKE.
//!
//! This file is a **dedicated, named conformance gate** — separate from the
//! existing implicit-rejection tests in `primitives_negative_tests_kem.rs`
//! and the bit-flip proptest in `tests/tests/proptest_invariants.rs` — so a
//! future change that accidentally introduces an error path into
//! `MlKem::decapsulate` for a correctly-sized ciphertext fails a test whose
//! name, file, and module-level documentation make the FIPS-203 conformance
//! intent unambiguous.
//!
//! Scope:
//! - All three security levels (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
//! - All three pathological-input categories called out in FIPS 203 §7.3
//!   (random / all-zero / all-one bytes), plus bit-flips of legitimate CTs
//! - Verifies BOTH that decap returns `Ok` AND that the rejected secret
//!   differs from the legitimate one (otherwise implicit rejection would be
//!   a no-op security-wise)
//!
//! What this file does NOT cover (and intentionally so — those belong
//! elsewhere):
//! - Wrong-length ciphertexts (parsed at construction time, not in §7.3 scope)
//! - Cross-parameter-set rejection (security-level mismatch — see
//!   `primitives_negative_tests_kem.rs`)

#![deny(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use latticearc::primitives::kem::ml_kem::{MlKem, MlKemCiphertext, MlKemSecurityLevel};
use subtle::ConstantTimeEq;

/// Single-level test driver. Parameterised over the security level so a
/// regression in any one level is caught individually with a named test.
fn assert_decapsulate_is_total(level: MlKemSecurityLevel) {
    let (pk, sk) = MlKem::generate_keypair(level).expect("keypair gen");
    let (legitimate_ss, legit_ct) = MlKem::encapsulate(&pk).expect("encapsulation");
    let ct_size = legit_ct.as_bytes().len();

    // Pathological-input categories. Each is a correctly-sized byte string
    // that is overwhelmingly unlikely to be a legitimate FO-output: random
    // bytes, all-zero, all-one, single-bit-flipped copies of the legitimate
    // ciphertext. Each MUST go through implicit rejection (return Ok with a
    // pseudorandom shared secret), not return Err.
    let mut pathological_cts: Vec<Vec<u8>> = vec![
        // Junk: 0x42 fill (looks like neither all-zero nor all-one)
        vec![0x42u8; ct_size],
        // All zeros
        vec![0u8; ct_size],
        // All ones
        vec![0xFFu8; ct_size],
    ];
    // Single-bit flips at three distinct positions in the legitimate CT
    for &flip_byte_index in &[0_usize, ct_size / 2, ct_size - 1] {
        let mut flipped = legit_ct.as_bytes().to_vec();
        flipped[flip_byte_index] ^= 0x01;
        pathological_cts.push(flipped);
    }

    for (case_idx, ct_bytes) in pathological_cts.into_iter().enumerate() {
        let ct = MlKemCiphertext::new(level, ct_bytes)
            .expect("construction with correct length always succeeds");
        let rejected = MlKem::decapsulate(&sk, &ct).unwrap_or_else(|e| {
            panic!(
                "FIPS 203 §7.3 violation: decapsulate({level:?}, pathological case {case_idx}) \
                 returned Err({e:?}) — must instead implicit-reject and return Ok",
            )
        });
        // Implicit rejection must yield a secret distinct from the legitimate
        // one — otherwise it would be a no-op and the IND-CCA2 reduction
        // would not go through.
        assert!(
            !bool::from(rejected.expose_secret().ct_eq(legitimate_ss.expose_secret())),
            "FIPS 203 §7.3 violation: implicit-rejection secret for {level:?} case {case_idx} \
             matched the legitimate shared secret — implicit rejection is a no-op"
        );
    }
}

#[test]
fn fips_203_section_7_3_decaps_is_total_for_ml_kem_512() {
    assert_decapsulate_is_total(MlKemSecurityLevel::MlKem512);
}

#[test]
fn fips_203_section_7_3_decaps_is_total_for_ml_kem_768() {
    assert_decapsulate_is_total(MlKemSecurityLevel::MlKem768);
}

#[test]
fn fips_203_section_7_3_decaps_is_total_for_ml_kem_1024() {
    assert_decapsulate_is_total(MlKemSecurityLevel::MlKem1024);
}

/// Determinism of implicit rejection: re-decapsulating the same invalid
/// ciphertext under the same secret key must yield the same fake secret.
/// FIPS 203 §7.3 derives the implicit-rejection secret deterministically
/// from `(z, c)` where `z` is part of the secret key and `c` is the
/// ciphertext, so two calls with the same inputs are required to agree.
#[test]
fn fips_203_section_7_3_implicit_rejection_is_deterministic() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (_pk, sk) = MlKem::generate_keypair(level).expect("keypair gen");
        let pathological = MlKemCiphertext::new(level, vec![0xA5u8; level.ciphertext_size()])
            .expect("construction with correct length");

        let first = MlKem::decapsulate(&sk, &pathological).expect("first decap is total");
        let second = MlKem::decapsulate(&sk, &pathological).expect("second decap is total");

        assert!(
            bool::from(first.expose_secret().ct_eq(second.expose_secret())),
            "FIPS 203 §7.3 violation: implicit rejection for {level:?} is non-deterministic — \
             two decapsulations of the same (sk, ct) returned different secrets"
        );
    }
}
