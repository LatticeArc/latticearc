#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for hybrid KEM (ML-KEM + X25519) with the 0.13 required
//! context: encapsulate/decapsulate roundtrip, context separation, and the
//! context-bound combiner on arbitrary inputs.

use latticearc::hybrid::kem_hybrid::{
    HybridSharedSecretInputs, decapsulate, decapsulate_with_context, derive_hybrid_shared_secret,
    derive_hybrid_shared_secret_with_context, encapsulate, encapsulate_with_context,
    generate_keypair_with_level,
};
use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use libfuzzer_sys::fuzz_target;
use subtle::ConstantTimeEq;

fn same(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let level = match data[0] % 3 {
        0 => MlKemSecurityLevel::MlKem512,
        1 => MlKemSecurityLevel::MlKem768,
        _ => MlKemSecurityLevel::MlKem1024,
    };
    let context = &data[1..];

    // Combiner on arbitrary (correctly sized) inputs: the context-bound
    // secret must be deterministic and differ from the context-less one.
    let mut ss_a = [0u8; 32];
    let mut ss_b = [0u8; 32];
    for (i, b) in data.iter().take(64).enumerate() {
        if i < 32 { ss_a[i] = *b } else { ss_b[i - 32] = *b }
    }
    let inputs = || HybridSharedSecretInputs {
        ml_kem_ss: &ss_a,
        ecdh_ss: &ss_b,
        ecdh_static_pk: &[1u8; 32],
        ml_kem_static_pk: &[2u8; 32],
        ephemeral_pk: &[3u8; 32],
        kem_ct: &[4u8; 32],
    };
    let bound = derive_hybrid_shared_secret_with_context(inputs(), context)
        .expect("non-empty context derives");
    let again = derive_hybrid_shared_secret_with_context(inputs(), context).expect("derives");
    assert!(same(bound.expose_secret(), again.expose_secret()));
    let plain = derive_hybrid_shared_secret(inputs()).expect("derives");
    assert!(!same(bound.expose_secret(), plain.expose_secret()));
    assert!(derive_hybrid_shared_secret_with_context(inputs(), &[]).is_err());

    // Full KEM roundtrip (keygen is the expensive step; bound to one per run).
    let (pk, sk) = match generate_keypair_with_level(level) {
        Ok(kp) => kp,
        Err(_) => return,
    };
    assert!(encapsulate_with_context(&pk, &[]).is_err());
    let enc = encapsulate_with_context(&pk, context).expect("encapsulate_with_context");
    let ss = decapsulate_with_context(&sk, &enc, context).expect("decapsulate_with_context");
    assert!(same(enc.expose_secret(), ss.expose_secret()), "roundtrip must agree");
    assert!(decapsulate_with_context(&sk, &enc, &[]).is_err());
    let mut other_ctx = context.to_vec();
    other_ctx[0] ^= 0xff;
    let other = decapsulate_with_context(&sk, &enc, &other_ctx).expect("decapsulates");
    assert!(!same(enc.expose_secret(), other.expose_secret()), "context must separate");
    let unbound = decapsulate(&sk, &enc).expect("decapsulates");
    assert!(!same(enc.expose_secret(), unbound.expose_secret()));
    let enc_plain = encapsulate(&pk).expect("encapsulate");
    let cross = decapsulate_with_context(&sk, &enc_plain, context).expect("decapsulates");
    assert!(!same(enc_plain.expose_secret(), cross.expose_secret()));
});
