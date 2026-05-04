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
//! # Two layers of dummy material
//!
//! - **Raw bytes** (`pq_pk`, `pq_sig`, `ed_pk`, `ed_sig`): zero-filled
//!   length-correct buffers. Used by the unified-API path's raw-byte
//!   interface; the consumer there re-parses internally via
//!   `verify_pq_ml_dsa_unverified(...).unwrap_or(false)` so a parse
//!   failure on the dummy collapses to `false` (today the parser is
//!   length-only so this is unreachable, but the `unwrap_or(false)`
//!   shape preserves verify-pipeline execution).
//!
//! - **Pre-parsed valid material** (`parsed: Option<HybridVerifyDummyParsed>`):
//!   real ML-DSA keypair + signature generated at init time, plus the
//!   exact test message that was signed. Used by [`sig_hybrid::verify`]
//!   when caller bytes fail the shape check OR fail to parse. Ensures
//!   `MlDsaPublicKey::verify` runs against guaranteed-valid material
//!   regardless of whether `from_bytes` ever adds content validation
//!   in a future `fips204` release. Post-85e2bd79e M1 audit fix —
//!   the previous design held raw bytes only and re-parsed at verify
//!   time, which would silently lose its equalizer property if
//!   `from_bytes` started rejecting zero-byte buffers.
//!
//! # Init fallibility
//!
//! `parsed` is `Option<HybridVerifyDummyParsed>` because keygen + sign
//! at init time is fallible (RNG failure, FIPS PCT failure, etc.).
//! When `parsed` is `None` (extremely rare path), the consumer falls
//! back to today's behavior: parse-fail → verify-skip. The equalizer
//! is best-effort defense-in-depth; the safety bound depends on
//! downstream code combining the verify result via bitwise AND with
//! `pq_shape_ok` so a missed equalization does not affect correctness,
//! only the strength of the timing-oracle countermeasure.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use crate::primitives::ec::ed25519::{Ed25519KeyPair, Ed25519Signature as Ed25519SignatureOps};
use crate::primitives::ec::traits::{EcKeyPair, EcSignature};
use crate::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};

/// Pre-parsed ML-DSA material for the verify-time equalizer fallback.
///
/// Generated lazily once per parameter set on first use of
/// [`hybrid_verify_dummy_material`]. The keypair is generated via
/// [`crate::primitives::sig::ml_dsa::generate_keypair`] and the
/// signature over [`Self::pq_test_message`] via
/// [`MlDsaSecretKey::sign`]. After init the secret key is dropped —
/// only the PK and signature need to live `'static` for the
/// equalizer; the SK has served its purpose by producing the
/// signature.
pub struct HybridVerifyDummyParsed {
    /// Real (validly-derived) ML-DSA public key for this parameter set.
    pub pq_pk: MlDsaPublicKey,
    /// Real ML-DSA signature, valid against `pq_pk` over `pq_test_message`.
    pub pq_sig: MlDsaSignature,
    /// The fixed test message that `pq_sig` signs. Verifying
    /// `pq_pk.verify(pq_test_message, pq_sig, &[])` MUST return
    /// `Ok(true)`. The message is intentionally NOT the caller's
    /// message — content-dependent verify timing is exactly what the
    /// equalizer is supposed to mask.
    pub pq_test_message: Vec<u8>,
}

/// Per-parameter-set cached zero-byte buffers + pre-parsed real
/// material used by both the `sig_hybrid::verify` and
/// `unified_api::verify_hybrid_ml_dsa_ed25519` timing equalizers.
///
/// The Ed25519 dummies are constant-size (32 / 64 bytes) and shared
/// across parameter sets but live in this struct for locality. No
/// secret material; safe to keep `'static`. The pre-parsed ML-DSA
/// material was generated at init from real keygen output — its
/// public components do not require zeroization.
pub struct HybridVerifyDummy {
    /// Raw zero-byte ML-DSA public key, length matches the parameter set.
    pub pq_pk: Vec<u8>,
    /// Raw zero-byte ML-DSA signature, length matches the parameter set.
    pub pq_sig: Vec<u8>,
    /// Raw zero-byte Ed25519 public key (32 bytes).
    pub ed_pk: Vec<u8>,
    /// Raw zero-byte Ed25519 signature (64 bytes).
    pub ed_sig: Vec<u8>,
    /// Round-29 L6: pre-parsed material is now wrapped in a `Mutex<Option<>>`
    /// so a transient init failure (RNG hiccup, FIPS PCT) doesn't
    /// permanently degrade the equalizer for the entire process
    /// lifetime. The previous `OnceLock<HybridVerifyDummy>` cached
    /// whatever the first init produced (including `None`). Now the
    /// outer cell still caches the `HybridVerifyDummy` shell, but
    /// callers go through [`Self::parsed_or_init`] which retries
    /// init when `parsed` is `None`. The `MlDsaParameterSet` is
    /// stored alongside so retries know which keypair to attempt.
    pub parsed: std::sync::Mutex<Option<HybridVerifyDummyParsed>>,
    /// Parameter set this dummy was constructed for (needed by the
    /// retry-on-None path to know which keypair to (re)init).
    pub param_set: MlDsaParameterSet,
}

impl HybridVerifyDummy {
    /// Round-29 L6: get the pre-parsed equalizer material, retrying
    /// the keygen+sign init when previous attempts produced `None`.
    /// Returns a clone of the parsed material (the parsed struct is
    /// cheap to clone — it holds public-key bytes and a signature, no
    /// secrets).
    ///
    /// Behaviour:
    /// - Some(parsed) cached → return clone immediately
    /// - None cached → attempt re-init; if successful cache and
    ///   return Some, otherwise leave None in place and return None
    ///
    /// Locking: a single Mutex serializes init attempts across
    /// threads. A failed init is fast; a successful init is rare
    /// (only on first-of-process or post-failure recovery).
    #[must_use]
    pub fn parsed_or_init(&self) -> Option<HybridVerifyDummyParsed> {
        // Avoid the `.unwrap()` lint by explicitly handling poison.
        let mut guard = match self.parsed.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = try_init_parsed(self.param_set);
        }
        guard.as_ref().map(HybridVerifyDummyParsed::clone)
    }
}

impl Clone for HybridVerifyDummyParsed {
    fn clone(&self) -> Self {
        Self {
            pq_pk: self.pq_pk.clone(),
            pq_sig: self.pq_sig.clone(),
            pq_test_message: self.pq_test_message.clone(),
        }
    }
}

/// Lazy-initialized per-parameter-set dummy material.
///
/// First call for each `param_set` allocates the zero buffers AND
/// attempts to generate a real ML-DSA keypair + sign a fixed test
/// message. The values are cached for the process lifetime. If
/// keygen or sign fails (extremely rare — RNG/PCT failure), the
/// `parsed` field stays `None` and the consumer falls back to the
/// legacy parse-then-verify path. The init closure is structured to
/// always succeed at constructing the raw-byte fields — only the
/// `parsed` field is fallible.
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
        parsed: std::sync::Mutex::new(try_init_parsed(param_set)),
        param_set,
    })
}

/// Best-effort init of the pre-parsed equalizer material. Returns
/// `None` on any failure — keygen RNG hiccup, FIPS PCT failure, sign
/// failure, etc. The caller (consumer of `HybridVerifyDummy`) must
/// treat `None` as "equalizer degraded for this parameter set, fall
/// back to legacy behavior".
fn try_init_parsed(param_set: MlDsaParameterSet) -> Option<HybridVerifyDummyParsed> {
    // Fixed test message: not security-sensitive, just a stable byte
    // string that's signed once at init and verified at every
    // equalizer-fallback. The label binds verify input to this
    // module's purpose so the cached signature is unmistakable as
    // dummy material if it ever leaks via debugging.
    let pq_test_message: Vec<u8> = b"latticearc/verify-equalizer/dummy-message-v1".to_vec();
    let (pq_pk, sk): (MlDsaPublicKey, MlDsaSecretKey) =
        crate::primitives::sig::ml_dsa::generate_keypair(param_set).ok()?;
    let pq_sig = sk.sign(&pq_test_message, &[]).ok()?;
    // SK is dropped here — its zeroization is handled by MlDsaSecretKey's
    // Drop impl (data is wrapped in Zeroizing).
    drop(sk);
    Some(HybridVerifyDummyParsed { pq_pk, pq_sig, pq_test_message })
}

/// Round-29 M1: Ed25519 timing equalizer. Pre-generated keypair +
/// signature whose verify cost (one EC scalar multiplication ≈ tens
/// of microseconds) matches a real Ed25519 verify. Used by
/// `sig_hybrid::verify` when the caller's Ed25519 signature bytes
/// fail the parse step — running verify against the cached material
/// makes the parse-fail path pay the same wall-clock as
/// parse-then-verify.
///
/// The previous `sig_hybrid` short-circuit ran no scalar mul on
/// length-fail, leaving a parse-vs-verify timing oracle that the
/// ML-DSA leg's equalizer mostly masked but couldn't close on the
/// Ed25519 side. The doc comment claimed "same order of magnitude"
/// but parse cost is empirically ~3 orders of magnitude smaller
/// than verify.
pub struct Ed25519VerifyDummy {
    /// Pre-parsed material; `Mutex<Option<>>` so a transient init
    /// failure can be retried (same posture as the ML-DSA equalizer).
    pub parsed: std::sync::Mutex<Option<Ed25519VerifyDummyParsed>>,
}

/// Inner parsed Ed25519 equalizer material — public PK bytes (32),
/// signature bytes (64), and the fixed test message they sign.
pub struct Ed25519VerifyDummyParsed {
    /// Real Ed25519 public key (32 bytes).
    pub ed_pk: Vec<u8>,
    /// Real Ed25519 signature (64 bytes), valid against `ed_pk` over `ed_test_message`.
    pub ed_sig: Vec<u8>,
    /// Fixed test message that `ed_sig` signs. Verifying against this
    /// is what consumes the verify-time wall-clock budget.
    pub ed_test_message: Vec<u8>,
}

impl Clone for Ed25519VerifyDummyParsed {
    fn clone(&self) -> Self {
        Self {
            ed_pk: self.ed_pk.clone(),
            ed_sig: self.ed_sig.clone(),
            ed_test_message: self.ed_test_message.clone(),
        }
    }
}

impl Ed25519VerifyDummy {
    /// Get pre-parsed Ed25519 equalizer material, retrying init when
    /// previous attempts produced None. Mirrors
    /// [`HybridVerifyDummy::parsed_or_init`].
    #[must_use]
    pub fn parsed_or_init(&self) -> Option<Ed25519VerifyDummyParsed> {
        let mut guard = match self.parsed.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = try_init_ed25519_parsed();
        }
        guard.as_ref().map(Ed25519VerifyDummyParsed::clone)
    }
}

/// Lazy-initialised Ed25519 equalizer material (process-wide).
#[must_use]
pub fn ed25519_verify_dummy_material() -> &'static Ed25519VerifyDummy {
    use std::sync::OnceLock;
    static CELL: OnceLock<Ed25519VerifyDummy> = OnceLock::new();
    CELL.get_or_init(|| Ed25519VerifyDummy {
        parsed: std::sync::Mutex::new(try_init_ed25519_parsed()),
    })
}

/// Best-effort init: keygen + sign over a fixed test message. Returns
/// None on RNG/PCT failure. Caller must treat None as "equalizer
/// degraded; fall back to legacy fast-fail."
fn try_init_ed25519_parsed() -> Option<Ed25519VerifyDummyParsed> {
    let test_message: Vec<u8> = b"latticearc/verify-equalizer/dummy-ed25519-v1".to_vec();
    let keypair = Ed25519KeyPair::generate().ok()?;
    let signature = keypair.sign(&test_message).ok()?;
    let ed_pk = keypair.public_key_bytes();
    let ed_sig = Ed25519SignatureOps::signature_bytes(&signature);
    // SK is dropped here — zeroized via Ed25519KeyPair Drop.
    drop(keypair);
    Some(Ed25519VerifyDummyParsed { ed_pk, ed_sig, ed_test_message: test_message })
}

#[cfg(test)]
#[allow(clippy::panic)] // Tests panic on missing init material
mod tests {
    use super::*;

    /// Locks the equalizer's contract: for every parameter set, the
    /// pre-parsed material verifies successfully. If a future change
    /// breaks keygen+sign init, this test catches it. (RNG failure
    /// is the only path to `None` and is not reachable in normal CI.)
    #[test]
    fn parsed_material_verifies_successfully_for_all_parameter_sets() {
        for param_set in
            [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
        {
            let dummy = hybrid_verify_dummy_material(param_set);
            // Round-29 L6: retrieve via the retry-on-None getter.
            let Some(parsed) = dummy.parsed_or_init() else {
                panic!("init keygen + sign must succeed under test conditions for {param_set:?}");
            };
            let result = parsed.pq_pk.verify(&parsed.pq_test_message, &parsed.pq_sig, &[]);
            assert!(
                matches!(result, Ok(true)),
                "pre-parsed equalizer material must self-verify for {:?}",
                param_set,
            );
        }
    }

    /// The raw-bytes fields preserve their pre-M1 contract: zero-filled,
    /// length-correct. Consumers that have not migrated to the parsed
    /// material continue to work.
    #[test]
    fn raw_byte_fields_preserve_legacy_contract() {
        for param_set in
            [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
        {
            let dummy = hybrid_verify_dummy_material(param_set);
            assert_eq!(dummy.pq_pk.len(), param_set.public_key_size());
            assert_eq!(dummy.pq_sig.len(), param_set.signature_size());
            assert!(dummy.pq_pk.iter().all(|&b| b == 0));
            assert!(dummy.pq_sig.iter().all(|&b| b == 0));
            assert_eq!(dummy.ed_pk.len(), 32);
            assert_eq!(dummy.ed_sig.len(), 64);
            assert!(dummy.ed_pk.iter().all(|&b| b == 0));
            assert!(dummy.ed_sig.iter().all(|&b| b == 0));
        }
    }
}
