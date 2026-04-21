//! Compile-time assertions that secret-holding types do NOT implement `PartialEq`.
//!
//! Without `PartialEq`, `==` does not compile on these types. That is the compile-
//! time barrier referenced by issue #49: it prevents a future contributor from
//! routing a secret comparison through `==` (which would be non-constant-time)
//! instead of `subtle::ConstantTimeEq::ct_eq`.
//!
//! If any of these types gains a `PartialEq` impl (derived or manual), this test
//! crate fails to compile, and CI rejects the change. The contributor must then
//! either (a) remove the `PartialEq`, or (b) replace these assertions with an
//! explicit documented exception that is reviewed in the PR.
//!
//! Scope: the 5 aws-lc-rs-wrapped types tracked by #49. We cannot implement
//! `ConstantTimeEq` on them directly (aws-lc-rs does not expose raw bytes), but
//! we *can* prevent `==` from being silently enabled.

use latticearc::primitives::kem::ecdh::{
    EcdhP256KeyPair, EcdhP384KeyPair, EcdhP521KeyPair, X25519KeyPair,
};
use latticearc::primitives::kem::ml_kem::MlKemDecapsulationKeyPair;
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(X25519KeyPair: PartialEq, Eq);
assert_not_impl_any!(EcdhP256KeyPair: PartialEq, Eq);
assert_not_impl_any!(EcdhP384KeyPair: PartialEq, Eq);
assert_not_impl_any!(EcdhP521KeyPair: PartialEq, Eq);
assert_not_impl_any!(MlKemDecapsulationKeyPair: PartialEq, Eq);
