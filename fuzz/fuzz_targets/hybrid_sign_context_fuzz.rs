#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the 0.13 hybrid signature transcript modes:
//! seed-derived keygen, `sign_with_context` / `verify_with_context` and
//! `sign_prehashed` / `verify_prehashed`, including cross-mode rejection.

use latticearc::hybrid::sig_hybrid::{
    MAX_HYBRID_SIG_CONTEXT_LEN, generate_keypair_from_seed, sign, sign_prehashed,
    sign_with_context, verify, verify_prehashed, verify_with_context,
};
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [0] parameter set, [1..33] seed, [33] context length selector,
    // then context bytes, then message bytes.
    if data.len() < 35 {
        return;
    }
    let param = match data[0] % 3 {
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    };
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[1..33]);
    let keypair = generate_keypair_from_seed(&seed, param);
    if seed.iter().all(|&b| b == 0) {
        assert!(keypair.is_err(), "all-zero seed must be rejected");
        return;
    }
    let (pk, sk) = keypair.expect("non-zero seed must derive a keypair");
    // Determinism: the same seed must give the same public keys.
    let (pk2, _) = generate_keypair_from_seed(&seed, param).expect("keygen is deterministic");
    assert_eq!(pk.ml_dsa_pk(), pk2.ml_dsa_pk());
    assert_eq!(pk.ed25519_pk(), pk2.ed25519_pk());

    let ctx_len = 1 + (data[33] as usize) % MAX_HYBRID_SIG_CONTEXT_LEN;
    let rest = &data[34..];
    let (context, message) =
        if rest.len() >= ctx_len { rest.split_at(ctx_len) } else { (rest, &[][..]) };
    if context.is_empty() {
        return;
    }
    let mut other_ctx = context.to_vec();
    other_ctx[0] ^= 0xff;

    // Context mode.
    let sig = sign_with_context(&sk, message, context).expect("sign_with_context");
    assert!(verify_with_context(&pk, message, &sig, context).expect("verify_with_context"));
    assert!(verify_with_context(&pk, message, &sig, &other_ctx).is_err());
    assert!(verify(&pk, message, &sig).is_err(), "context-mode signature must not verify plain");
    let plain = sign(&sk, message).expect("sign");
    assert!(verify(&pk, message, &plain).expect("verify"));
    assert!(verify_with_context(&pk, message, &plain, context).is_err());

    // Pre-hashed mode: any 64 bytes are a valid digest input.
    let mut digest = [0u8; 64];
    let take = message.len().min(64);
    digest[..take].copy_from_slice(&message[..take]);
    let ph = sign_prehashed(&sk, &digest, context).expect("sign_prehashed");
    assert!(verify_prehashed(&pk, &digest, &ph, context).expect("verify_prehashed"));
    assert!(verify_prehashed(&pk, &digest, &ph, &other_ctx).is_err());
    assert!(verify_prehashed(&pk, &digest, &sig, context).is_err());
    assert!(verify_with_context(&pk, &digest, &ph, context).is_err());
    assert!(verify(&pk, &digest, &ph).is_err());

    // Argument validation never panics.
    assert!(sign_with_context(&sk, message, &[]).is_err());
    assert!(sign_prehashed(&sk, &digest, &[]).is_err());
    assert!(sign_prehashed(&sk, &digest[..63], context).is_err());
    let too_long = vec![0u8; MAX_HYBRID_SIG_CONTEXT_LEN + 1];
    assert!(sign_with_context(&sk, message, &too_long).is_err());
});
