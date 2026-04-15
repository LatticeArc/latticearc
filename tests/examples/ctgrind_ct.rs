//! Valgrind-based (ctgrind) constant-time harness.
//!
//! Complementary to the DudeCT statistical gate (`examples/dudect_ct.rs`).
//! Where dudect detects timing variance at the nanosecond scale,
//! ctgrind works at the instruction level: we mark the bytes of each
//! secret input as `Undefined` via Valgrind's memcheck client request,
//! then invoke the CT operation. Valgrind will flag any branch or
//! array index that depends on those "uninitialized" bytes — which
//! is equivalent to the program's observable behavior depending on
//! the secret.
//!
//! This is the same technique used by BoringSSL's `ctgrind` and by
//! the `ctgrind`-style harnesses in libsodium and aws-lc.
//!
//! Constraints:
//! - **Must run under Valgrind.** Outside Valgrind, the memcheck
//!   requests are no-ops by design but the example still completes;
//!   no false positives, just no coverage. The workflow `ctgrind.yml`
//!   wraps this binary with `valgrind --error-exitcode=1` so any
//!   CT violation becomes a CI failure.
//! - **Pure-Rust code paths only.** Valgrind cannot cleanly reason
//!   about aws-lc-rs assembly (it would conflate C-level ops with
//!   data that Rust considers CT). We therefore target operations
//!   that stay on the `subtle` side of the stack.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

use core::ffi::c_void;
use std::hint::black_box;

use crabgrind::memcheck::{MemState, mark_memory};
use subtle::ConstantTimeEq;

use latticearc::hybrid::kem_hybrid::{HybridKemSecretKey, generate_keypair};

/// Mark `bytes` as uninitialized from Valgrind's perspective. Any
/// subsequent branch or index based on those bytes raises an error.
fn mark_secret(bytes: &[u8]) {
    // `mark_memory` returns `Err(UnaddressableBytes)` if the range is
    // unaddressable. For stack- or heap-backed `&[u8]` it always
    // succeeds; we discard the Result intentionally (errors here
    // mean valgrind is not running, which the workflow ensures).
    let _ = mark_memory(bytes.as_ptr() as *const c_void, bytes.len(), MemState::Undefined);
}

// -----------------------------------------------------------------------------
// Check 1: `subtle::ConstantTimeEq` on raw byte arrays.
//
// Establishes the baseline — if subtle itself leaks, every caller is
// suspect. `subtle` uses XOR + OR accumulation and `black_box` to
// prevent the optimizer from inserting branches; valgrind should see
// no branch on the marked bytes.
// -----------------------------------------------------------------------------
fn check_subtle_ct_eq_equal() {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    mark_secret(&a);
    mark_secret(&b);
    // `black_box` prevents the compiler from folding the known-equal
    // pair into a constant `Choice::from(1)`.
    let _ = black_box(a.ct_eq(&b));
}

fn check_subtle_ct_eq_unequal() {
    let a = [0x42u8; 32];
    let mut b = a;
    b[17] ^= 1;
    mark_secret(&a);
    mark_secret(&b);
    let _ = black_box(a.ct_eq(&b));
}

// -----------------------------------------------------------------------------
// Check 2: `HybridKemSecretKey::ct_eq` on real keys.
//
// Exercises the ct_eq impl landed in bfeb9b0e end-to-end: the level
// comparison (public parameter, not marked), the ML-KEM byte compare,
// and the ECDH seed compare. Both sides equal = single-iteration of
// the all-legs-true path.
// -----------------------------------------------------------------------------
fn check_hybrid_ct_eq_equal() {
    let (_, sk) = generate_keypair().expect("hybrid keygen");
    let ml_sk = sk.ml_kem_sk_bytes().expect("ml_kem bytes");
    let ml_pk = sk.ml_kem_pk_bytes();
    let ecdh_seed = sk.ecdh_seed_bytes().expect("ecdh seed");
    let sk_dup =
        HybridKemSecretKey::from_serialized(sk.security_level(), &ml_sk, &ml_pk, &ecdh_seed)
            .expect("reconstruct sk");

    // Mark the byte-level secrets as Undefined. (security_level is
    // not marked — it is a public parameter, and its comparison
    // legitimately branches on a non-secret bool.)
    mark_secret(&ml_sk);
    mark_secret(ecdh_seed.as_ref());

    let _ = black_box(sk.ct_eq(&sk_dup));
}

fn check_hybrid_ct_eq_unequal() {
    let (_, sk_a) = generate_keypair().expect("hybrid keygen a");
    let (_, sk_b) = generate_keypair().expect("hybrid keygen b");

    let ml_sk_a = sk_a.ml_kem_sk_bytes().expect("ml_kem bytes");
    let ecdh_a = sk_a.ecdh_seed_bytes().expect("ecdh seed");
    mark_secret(&ml_sk_a);
    mark_secret(ecdh_a.as_ref());

    let _ = black_box(sk_a.ct_eq(&sk_b));
}

fn main() {
    check_subtle_ct_eq_equal();
    check_subtle_ct_eq_unequal();
    check_hybrid_ct_eq_equal();
    check_hybrid_ct_eq_unequal();
    println!("ctgrind harness complete (4 checks)");
}
