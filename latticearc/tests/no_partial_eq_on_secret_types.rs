//! Compile-time assertions that secret-holding types do NOT implement `PartialEq` or `Eq`.
//!
//! Without `PartialEq`, `==` does not compile on these types. This is the
//! compile-time barrier required by Secret Type Invariant **I-6** (see
//! `docs/SECRET_TYPE_INVARIANTS.md`): it prevents a future contributor from
//! routing a secret comparison through `==` (which is non-constant-time and
//! leaks prefix agreement via short-circuit evaluation) instead of
//! [`subtle::ConstantTimeEq::ct_eq`].
//!
//! If any listed type gains a `PartialEq` or `Eq` impl (derived or manual),
//! this test crate fails to compile, and CI rejects the change. The contributor
//! must then either (a) remove the trait impl, or (b) replace these assertions
//! with an explicit, documented exception reviewed in the PR.
//!
//! # Coverage scope
//!
//! Every `pub` type in the `latticearc` crate that holds secret material per
//! the Secret Type Invariant spec. See `docs/SECRET_TYPE_INVARIANTS.md` for the
//! definition of what counts as secret material.
//!
//! # Adding a new secret type
//!
//! If you add a new `pub` type that holds secret material, you MUST add a
//! corresponding `assert_not_impl_any!` line here. The CI script
//! `scripts/ci/secret_type_audit.sh` (planned) will automate this check.

// Generic primitives
use latticearc::types::{SecretBytes, SecretVec};
use latticearc::{PrivateKey, SymmetricKey};

// KEM primitives
use latticearc::primitives::kem::ecdh::{
    EcdhP256KeyPair, EcdhP384KeyPair, EcdhP521KeyPair, X25519KeyPair, X25519SecretKey,
    X25519StaticKeyPair,
};
use latticearc::primitives::kem::ml_kem::{
    MlKemDecapsulationKeyPair, MlKemSecretKey, MlKemSharedSecret,
};

// Signature primitives
use latticearc::primitives::ec::ed25519::Ed25519KeyPair;
// Secp256k1 is gated off under `--features fips` (not a NIST-approved curve).
#[cfg(not(feature = "fips"))]
use latticearc::primitives::ec::secp256k1::Secp256k1KeyPair;
use latticearc::primitives::sig::fndsa::{KeyPair as FnDsaKeyPair, SigningKey as FnDsaSigningKey};
use latticearc::primitives::sig::ml_dsa::MlDsaSecretKey;
use latticearc::primitives::sig::slh_dsa::SigningKey as SlhDsaSigningKey;

// Hybrid compositions
use latticearc::hybrid::kem_hybrid::{EncapsulatedKey, HybridKemSecretKey};
use latticearc::hybrid::pq_only::PqOnlySecretKey;
use latticearc::hybrid::sig_hybrid::HybridSigSecretKey;

// ZKP types (proofs contain witness-derived randomness; openings contain the
// witness). The `zkp` module is gated off under `--features fips` because it
// uses non-FIPS-approved EC operations, so these imports are cfg-gated to match.
#[cfg(not(feature = "fips"))]
use latticearc::zkp::{DlogEqualityProof, HashOpening, PedersenOpening, SchnorrProof, SigmaProof};

// Serialization
use latticearc::unified_api::serialization::SerializableKeyPair;

use static_assertions::assert_not_impl_any;

// ============================================================================
// Generic primitive secret containers
// ============================================================================

assert_not_impl_any!(SecretBytes<1>: PartialEq, Eq);
assert_not_impl_any!(SecretBytes<32>: PartialEq, Eq);
assert_not_impl_any!(SecretBytes<64>: PartialEq, Eq);
assert_not_impl_any!(SecretVec: PartialEq, Eq);
assert_not_impl_any!(PrivateKey: PartialEq, Eq);
assert_not_impl_any!(SymmetricKey: PartialEq, Eq);

// ============================================================================
// KEM
// ============================================================================

assert_not_impl_any!(X25519SecretKey: PartialEq, Eq);
assert_not_impl_any!(X25519KeyPair: PartialEq, Eq);
assert_not_impl_any!(X25519StaticKeyPair: PartialEq, Eq);
assert_not_impl_any!(EcdhP256KeyPair: PartialEq, Eq);
assert_not_impl_any!(EcdhP384KeyPair: PartialEq, Eq);
assert_not_impl_any!(EcdhP521KeyPair: PartialEq, Eq);
assert_not_impl_any!(MlKemSecretKey: PartialEq, Eq);
assert_not_impl_any!(MlKemSharedSecret: PartialEq, Eq);
assert_not_impl_any!(MlKemDecapsulationKeyPair: PartialEq, Eq);

// ============================================================================
// Signatures
// ============================================================================

assert_not_impl_any!(MlDsaSecretKey: PartialEq, Eq);
assert_not_impl_any!(SlhDsaSigningKey: PartialEq, Eq);
assert_not_impl_any!(FnDsaSigningKey: PartialEq, Eq);
assert_not_impl_any!(FnDsaKeyPair: PartialEq, Eq);
assert_not_impl_any!(Ed25519KeyPair: PartialEq, Eq);
#[cfg(not(feature = "fips"))]
assert_not_impl_any!(Secp256k1KeyPair: PartialEq, Eq);

// ============================================================================
// Hybrid
// ============================================================================

assert_not_impl_any!(HybridKemSecretKey: PartialEq, Eq);
assert_not_impl_any!(HybridSigSecretKey: PartialEq, Eq);
assert_not_impl_any!(PqOnlySecretKey: PartialEq, Eq);
// EncapsulatedKey holds a `SecretBytes<64>` shared secret. Its equality is
// timing-sensitive — already has ConstantTimeEq, must not gain PartialEq.
assert_not_impl_any!(EncapsulatedKey: PartialEq, Eq);

// ============================================================================
// ZKP (not compiled under `fips` feature — see `lib.rs` cfg gate on `zkp`)
// ============================================================================

// Proofs embed witness-derived randomness; treat as secret material.
#[cfg(not(feature = "fips"))]
assert_not_impl_any!(SchnorrProof: PartialEq, Eq);
#[cfg(not(feature = "fips"))]
assert_not_impl_any!(SigmaProof: PartialEq, Eq);
#[cfg(not(feature = "fips"))]
assert_not_impl_any!(DlogEqualityProof: PartialEq, Eq);
// Openings reveal the committed witness.
#[cfg(not(feature = "fips"))]
assert_not_impl_any!(HashOpening: PartialEq, Eq);
#[cfg(not(feature = "fips"))]
assert_not_impl_any!(PedersenOpening: PartialEq, Eq);

// ============================================================================
// Serialization
// ============================================================================

assert_not_impl_any!(SerializableKeyPair: PartialEq, Eq);
