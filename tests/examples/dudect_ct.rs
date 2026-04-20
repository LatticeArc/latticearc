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
// Left:  (sk_a, sk_a_dup) — sk_a_dup is byte-for-byte equal to sk_a
// Right: (sk_a, sk_b_dup) — sk_b_dup is byte-for-byte equal to an
//                           independently generated `sk_b`
//
// Both `other` operands are reconstructed via `from_serialized` so that
// their internal aws-lc-rs representations match. This matters because
// `HybridKemSecretKey::ct_eq` calls `ml_kem_sk_bytes()` on both operands
// (an aws-lc-rs FFI `DecapsulationKey::key_bytes()` call), and a key
// reconstructed from serialized bytes can take different wall-clock
// time to re-serialize than a key created directly by `generate_keypair`.
// A previous version of this bench used `sk_b` (native) on the Right and
// `sk_a_dup` (from_serialized) on the Left, producing a |t| around 18
// purely from that origin asymmetry — not from any content-dependent
// branch in the comparison itself.
//
// With the setup below, the ONLY material difference between the two
// classes is whether the underlying byte arrays are equal or not; any
// detected timing distinguishability must come from the `subtle::
// ConstantTimeEq` path.
// -----------------------------------------------------------------------------
fn bench_hybrid_secret_key_ct_eq(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // Generate a stable pool of keys upfront.
    let (_, sk_a) = generate_keypair().expect("hybrid keygen");
    let (_, sk_b) = generate_keypair().expect("hybrid keygen");

    // Reconstruct both operands via `from_serialized` so their internal
    // aws-lc-rs representation is identical across the two classes.
    let reconstruct = |sk: &HybridKemSecretKey| -> HybridKemSecretKey {
        let ml_sk = sk.ml_kem_sk_bytes().expect("ml_kem sk bytes");
        let ml_pk = sk.ml_kem_pk_bytes();
        let ecdh_seed = sk.ecdh_seed_bytes().expect("ecdh seed bytes");
        HybridKemSecretKey::from_serialized(sk.security_level(), &ml_sk, &ml_pk, &ecdh_seed)
            .expect("reconstruct secret key")
    };
    let sk_a_dup = reconstruct(&sk_a);
    let sk_b_dup = reconstruct(&sk_b);

    for i in 0..SAMPLES {
        if i % 2 == 0 {
            // Equal keys (byte-for-byte identical to sk_a).
            runner.run_one(Class::Left, || {
                let _c = sk_a.ct_eq(&sk_a_dup);
            });
        } else {
            // Different keys (independently generated sk_b, reconstructed).
            runner.run_one(Class::Right, || {
                let _c = sk_a.ct_eq(&sk_b_dup);
            });
        }
    }
}

ctbench_main!(bench_verify_hmac_sha256, bench_hybrid_secret_key_ct_eq);
