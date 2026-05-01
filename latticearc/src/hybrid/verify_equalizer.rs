//! Shared timing-equalizer dummy material for hybrid signature verify.
//!
//! Both [`crate::hybrid::sig_hybrid::verify`] (typed-input lower-level
//! path) and [`crate::unified_api::convenience::api::verify_hybrid_ml_dsa_ed25519`]
//! (raw-byte unified-API path) need shape-correct stand-in inputs to
//! substitute when a caller-supplied PK or signature fails the shape
//! check. Running the verify pipeline against the substitute keeps
//! wall-clock cost equal between shape-fail and verify-fail, removing
//! the timing oracle that opaque error returns alone do not close.
//!
//! Both layers consume the dummy as raw bytes (and re-parse internally
//! via the same `verify_pq_ml_dsa_unverified` entry point). Holding raw
//! bytes only — no pre-parsed structures — means this module contains
//! no fallible operations: the cache stays infallibly initializable
//! without any `expect` / `panic` / `#[allow]` escape hatches.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use crate::primitives::sig::ml_dsa::MlDsaParameterSet;

/// Per-parameter-set cached zero-byte buffers used by both the
/// `sig_hybrid::verify` and `unified_api::verify_hybrid_ml_dsa_ed25519`
/// timing equalizers.
///
/// The Ed25519 dummies are constant-size (32 / 64 bytes) and shared
/// across parameter sets but live in this struct for locality. No
/// secret material; safe to keep `'static`.
pub struct HybridVerifyDummy {
    /// Raw zero-byte ML-DSA public key, length matches the parameter set.
    pub pq_pk: Vec<u8>,
    /// Raw zero-byte ML-DSA signature, length matches the parameter set.
    pub pq_sig: Vec<u8>,
    /// Raw zero-byte Ed25519 public key (32 bytes).
    pub ed_pk: Vec<u8>,
    /// Raw zero-byte Ed25519 signature (64 bytes).
    pub ed_sig: Vec<u8>,
}

/// Lazy-initialized per-parameter-set dummy material.
///
/// First call for each `param_set` allocates the zero buffers; the
/// values are cached for the process lifetime. The init closure is
/// infallible — only `Vec` allocations, no parse, no `expect`.
#[must_use]
pub fn hybrid_verify_dummy_material(param_set: MlDsaParameterSet) -> &'static HybridVerifyDummy {
    use std::sync::OnceLock;

    static M44: OnceLock<HybridVerifyDummy> = OnceLock::new();
    static M65: OnceLock<HybridVerifyDummy> = OnceLock::new();
    static M87: OnceLock<HybridVerifyDummy> = OnceLock::new();

    let cell = match param_set {
        MlDsaParameterSet::MlDsa44 => &M44,
        MlDsaParameterSet::MlDsa65 => &M65,
        MlDsaParameterSet::MlDsa87 => &M87,
    };
    cell.get_or_init(|| HybridVerifyDummy {
        pq_pk: vec![0u8; param_set.public_key_size()],
        pq_sig: vec![0u8; param_set.signature_size()],
        ed_pk: vec![0u8; 32],
        ed_sig: vec![0u8; 64],
    })
}
