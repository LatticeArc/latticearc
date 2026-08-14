//! FIPS 140-3 §9.6 operational-gate coverage across the convenience API.
//!
//! §9.6 requires that a module in an error state provide no cryptographic
//! services. The convenience API is the surface most consumers actually call,
//! so *every* entry point on it that performs an approved-algorithm operation
//! must consult the operational latch — not just the `unified_api::encrypt` /
//! `decrypt` / `sign` / `verify` quartet.
//!
//! The gap this file pins: the AEAD, hash/KDF/MAC, PQ KEM, PQ signature,
//! Ed25519, hybrid-signature and ECDSA-P384 convenience modules each reach
//! `crate::primitives::*` directly. A consumer using only those modules would,
//! before this was fixed, keep performing crypto after the module had entered
//! an error state.
//!
//! Every assertion here runs in one test function on purpose: the latch is
//! process-global state, so interleaving with a second `#[test]` in this
//! binary would race.

// `self_test` error-state control requires both features: `fips-self-test`
// makes `fips_verify_operational` a real check rather than a no-op, and
// `test-utils` exposes the §9.6 recovery helpers.
#![cfg(all(feature = "fips-self-test", feature = "test-utils"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use latticearc::primitives::ec::traits::EcKeyPair as _;
use latticearc::primitives::kem::MlKemSecurityLevel;
use latticearc::primitives::self_test::{
    ModuleErrorCode, clear_error_state, initialize_and_test, set_module_error,
};
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc::unified_api::zero_trust::SecurityMode;

const KEM_LEVEL: MlKemSecurityLevel = MlKemSecurityLevel::MlKem768;
const DSA_PARAMS: MlDsaParameterSet = MlDsaParameterSet::MlDsa65;

/// Records one convenience entry point that kept working in the error state.
macro_rules! assert_refused {
    ($failures:expr, $label:literal, $call:expr) => {
        if $call.is_ok() {
            $failures.push($label);
        }
    };
}

#[test]
fn test_every_convenience_entry_point_refuses_service_in_error_state_fails() {
    // Establish a known-good operational state first, so an Ok() below would
    // genuinely mean "the gate is missing" rather than "the module never
    // initialized".
    clear_error_state();
    let _ = initialize_and_test();

    // Fixtures built while the module is still operational — construction
    // must not be what fails once we trip the latch.
    let key = [7u8; 32];
    let data = b"operational gate coverage";

    let (ml_kem_pk, ml_kem_sk) =
        latticearc::unified_api::generate_ml_kem_keypair(KEM_LEVEL).unwrap();
    let (ml_kem_pk, ml_kem_sk) =
        (ml_kem_pk.as_slice().to_vec(), ml_kem_sk.expose_secret().to_vec());
    let (ml_dsa_pk, ml_dsa_sk) =
        latticearc::primitives::sig::ml_dsa::generate_keypair(DSA_PARAMS).unwrap();
    let (ml_dsa_pk, ml_dsa_sk) =
        (ml_dsa_pk.as_bytes().to_vec(), ml_dsa_sk.expose_secret().to_vec());
    let (hyb_sig_pk, hyb_sig_sk) =
        latticearc::unified_api::generate_hybrid_signing_keypair_unverified().unwrap();
    let ed_kp = latticearc::primitives::ec::ed25519::Ed25519KeyPair::generate().unwrap();
    let (ed_pk, ed_sk) = (ed_kp.public_key_bytes(), ed_kp.secret_key_bytes());

    let aes_ct = latticearc::unified_api::encrypt_aes_gcm_unverified(data, &key).unwrap();
    let ed_sig = latticearc::unified_api::sign_ed25519_unverified(data, &ed_sk).unwrap();
    let hyb_sig = latticearc::unified_api::sign_hybrid_unverified(data, &hyb_sig_sk).unwrap();
    let ml_dsa_sig =
        latticearc::unified_api::sign_pq_ml_dsa_unverified(data, &ml_dsa_sk, DSA_PARAMS).unwrap();
    let pq_ct =
        latticearc::unified_api::encrypt_pq_ml_kem_unverified(data, &ml_kem_pk, KEM_LEVEL).unwrap();

    // FIPS 140-3 §9.6: enter the error state. From here on, no cryptographic
    // service may succeed.
    set_module_error(ModuleErrorCode::SelfTestFailure);

    let mut failures: Vec<&'static str> = Vec::new();

    // --- aes_gcm ---
    assert_refused!(
        failures,
        "aes_gcm::encrypt_aes_gcm_unverified",
        latticearc::unified_api::encrypt_aes_gcm_unverified(data, &key)
    );
    assert_refused!(
        failures,
        "aes_gcm::decrypt_aes_gcm_unverified",
        latticearc::unified_api::decrypt_aes_gcm_unverified(&aes_ct, &key)
    );
    assert_refused!(
        failures,
        "aes_gcm::encrypt_aes_gcm (SecurityMode)",
        latticearc::unified_api::encrypt_aes_gcm(data, &key, SecurityMode::Unverified)
    );

    // --- hashing (hash / KDF / MAC) ---
    assert_refused!(failures, "hashing::hash_data", latticearc::unified_api::hash_data(data));
    assert_refused!(
        failures,
        "hashing::derive_key_unverified",
        latticearc::unified_api::derive_key_unverified(b"passphrase", b"salt-value-16byt", 32)
    );
    assert_refused!(
        failures,
        "hashing::hmac_unverified",
        latticearc::unified_api::hmac_unverified(data, &key)
    );

    // --- pq_kem ---
    assert_refused!(
        failures,
        "pq_kem::encrypt_pq_ml_kem_unverified",
        latticearc::unified_api::encrypt_pq_ml_kem_unverified(data, &ml_kem_pk, KEM_LEVEL)
    );
    assert_refused!(
        failures,
        "pq_kem::decrypt_pq_ml_kem_unverified",
        latticearc::unified_api::decrypt_pq_ml_kem_unverified(&pq_ct, &ml_kem_sk, KEM_LEVEL)
    );

    // --- pq_sig ---
    assert_refused!(
        failures,
        "pq_sig::sign_pq_ml_dsa_unverified",
        latticearc::unified_api::sign_pq_ml_dsa_unverified(data, &ml_dsa_sk, DSA_PARAMS)
    );
    assert_refused!(
        failures,
        "pq_sig::verify_pq_ml_dsa_unverified",
        latticearc::unified_api::verify_pq_ml_dsa_unverified(
            data,
            &ml_dsa_sig,
            &ml_dsa_pk,
            DSA_PARAMS
        )
    );

    // --- ed25519 ---
    assert_refused!(
        failures,
        "ed25519::sign_ed25519_unverified",
        latticearc::unified_api::sign_ed25519_unverified(data, &ed_sk)
    );
    assert_refused!(
        failures,
        "ed25519::verify_ed25519_unverified",
        latticearc::unified_api::verify_ed25519_unverified(data, &ed_sig, &ed_pk)
    );

    // --- hybrid_sig ---
    assert_refused!(
        failures,
        "hybrid_sig::generate_hybrid_signing_keypair_unverified",
        latticearc::unified_api::generate_hybrid_signing_keypair_unverified()
    );
    assert_refused!(
        failures,
        "hybrid_sig::sign_hybrid_unverified",
        latticearc::unified_api::sign_hybrid_unverified(data, &hyb_sig_sk)
    );
    assert_refused!(
        failures,
        "hybrid_sig::verify_hybrid_signature_unverified",
        latticearc::unified_api::verify_hybrid_signature_unverified(data, &hyb_sig, &hyb_sig_pk)
    );

    // Restore before asserting so a failure here cannot leave the process-wide
    // latch tripped for anything that runs after.
    clear_error_state();
    let _ = initialize_and_test();

    assert!(
        failures.is_empty(),
        "FIPS 140-3 §9.6 violation — these convenience entry points performed \
         cryptographic operations while the module was in an error state:\n  {}",
        failures.join("\n  ")
    );
}
