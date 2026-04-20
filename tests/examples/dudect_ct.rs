//! DudeCT statistical constant-time harness.
//!
//! Runs Welch's t-test across two input classes for selected operations.
//! A large `|t|` (conventionally > 5) is strong statistical evidence that
//! the operation's runtime depends on secret data — i.e., a timing side
//! channel. Small `|t|` is *not* a proof of constant-timeness (the chosen
//! input distribution might not exercise the leak), but it's the standard
//! empirical check used by the crypto literature since Reparaz et al.'s
//! DudeCT paper (2016/1123).
//!
//! Invoke via:
//!     cargo run --release --example dudect_ct -p latticearc-tests
//!
//! Output format (per bench):
//!     bench <name> ... : n == +X.XXXM, max t = +Y.YYYYY, max tau = ...
//!
//! The `.github/workflows/dudect.yml` workflow parses `max t` and fails if
//! any bench produces `|max t| > DUDECT_T_THRESHOLD` (default 10 —
//! conservative vs. the paper's 5 to absorb shared-runner noise).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};

use latticearc::hybrid::kem_hybrid::{HybridKemSecretKey, generate_keypair};
use latticearc::primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};
use subtle::ConstantTimeEq;

const SAMPLES: usize = 100_000;

// -----------------------------------------------------------------------------
// Bench 1: `verify_hmac_sha256` timing under valid vs. tampered tags.
//
// Left:  (key, message, valid_tag)
// Right: (key, message, valid_tag with one byte flipped)
//
// A naive byte-by-byte tag compare would return at the first differing
// byte, producing a massive t-statistic. Our implementation calls
// `aws-lc-rs`'s `hmac::verify`, which uses constant-time comparison.
// -----------------------------------------------------------------------------
fn bench_verify_hmac_sha256(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // Prepare inputs outside the measured region so allocation cost doesn't
    // contaminate the timing samples.
    let key = [0x42u8; 32];
    let message = b"latticearc dudect probe message".to_vec();
    let valid_tag = hmac_sha256(&key, &message).expect("hmac");
    let mut tampered_tag = valid_tag;
    tampered_tag[0] ^= 0xFF;

    let mut inputs: Vec<([u8; 32], Class)> = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        if i % 2 == 0 {
            inputs.push((valid_tag, Class::Left));
        } else {
            inputs.push((tampered_tag, Class::Right));
        }
    }

    for (tag, class) in inputs {
        runner.run_one(class, || {
            let _ = verify_hmac_sha256(&key, &message, &tag);
        });
    }
}

// -----------------------------------------------------------------------------
// Bench 2: `HybridKemSecretKey::ct_eq` timing on equal vs. differing keys.
//
// Left:  sk_a.ct_eq(equal_pool[i])  — bytes identical to sk_a
// Right: sk_a.ct_eq(diff_pool[i])   — bytes differ from sk_a
//
// Each class draws its `other` operand from a pool of POOL_SIZE
// independently-allocated keys so per-sample heap addresses are drawn
// from the same distribution in both classes. That eliminates
// allocation-layout bias and leaves content-dependent work in `ct_eq`
// as the only possible source of a t-signal.
// -----------------------------------------------------------------------------
fn bench_hybrid_secret_key_ct_eq(runner: &mut CtRunner, _rng: &mut BenchRng) {
    const POOL_SIZE: usize = 32;

    let (_, sk_a) = generate_keypair().expect("hybrid keygen");

    // Build a pool of keys byte-equal to `sk_a` by round-tripping its
    // serialized components through `from_serialized`. Each pool element
    // is an independent heap allocation.
    let ml_sk_a = sk_a.ml_kem_sk_bytes().expect("ml_kem sk bytes");
    let ml_pk_a = sk_a.ml_kem_pk_bytes();
    let ecdh_seed_a = sk_a.ecdh_seed_bytes().expect("ecdh seed bytes");
    let clone_sk_a = || {
        HybridKemSecretKey::from_serialized(sk_a.security_level(), &ml_sk_a, &ml_pk_a, &ecdh_seed_a)
            .expect("reconstruct equal key")
    };
    let equal_pool: Vec<HybridKemSecretKey> = (0..POOL_SIZE).map(|_| clone_sk_a()).collect();
    let diff_pool: Vec<HybridKemSecretKey> =
        (0..POOL_SIZE).map(|_| generate_keypair().expect("hybrid keygen").1).collect();

    // Independent indices per class so Left and Right each traverse the
    // full 0..POOL_SIZE range of their respective pool rather than only
    // the even/odd subset dictated by the global sample counter.
    let mut left_idx = 0usize;
    let mut right_idx = 0usize;
    for i in 0..SAMPLES {
        if i % 2 == 0 {
            let idx = left_idx % POOL_SIZE;
            left_idx = left_idx.wrapping_add(1);
            runner.run_one(Class::Left, || {
                let _c = sk_a.ct_eq(&equal_pool[idx]);
            });
        } else {
            let idx = right_idx % POOL_SIZE;
            right_idx = right_idx.wrapping_add(1);
            runner.run_one(Class::Right, || {
                let _c = sk_a.ct_eq(&diff_pool[idx]);
            });
        }
    }
}

ctbench_main!(bench_verify_hmac_sha256, bench_hybrid_secret_key_ct_eq);
