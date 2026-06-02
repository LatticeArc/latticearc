//! DudeCT statistical constant-time harness.
//!
//! Runs Welch's t-test across two input classes for the single code path
//! whose CT property cannot be checked by `ctgrind.yml`:
//! `HmacSha256Verifier::verify`, which touches aws-lc-rs FFI that
//! Valgrind-memcheck cannot cleanly reason about.
//!
//! A large `|t|` (conventionally > 5) is strong statistical evidence that
//! the operation's runtime depends on secret data — i.e., a timing side
//! channel. Small `|t|` is *not* a proof of constant-timeness (the chosen
//! input distribution might not exercise the leak), but it's the standard
//! empirical check used by the crypto literature since Reparaz et al.'s
//! DudeCT paper (2016/1123).
//!
//! Pure-Rust paths (including `HybridKemSecretKey::ct_eq`) are verified
//! by `tests/examples/ctgrind_ct.rs` under Valgrind memcheck instead —
//! that gives a deterministic instruction-level oracle without the
//! shared-runner statistical noise dudect is sensitive to.
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

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};

use latticearc::primitives::mac::hmac::{HmacSha256Verifier, hmac_sha256};

const SAMPLES: usize = 100_000;

// -----------------------------------------------------------------------------
// `HmacSha256Verifier::verify` timing under valid vs. tampered tags.
//
// Left:  verifier.verify(message, valid_tag)
// Right: verifier.verify(message, valid_tag with one byte flipped)
//
// Uses `HmacSha256Verifier` (key bound once at construction) rather than
// the one-shot `verify_hmac_sha256(key, data, tag)` so the measured region
// doesn't include an aws-lc-rs `hmac::Key::new` FFI allocation on every
// iteration. That allocator churn would otherwise drift the per-sample
// baseline and produce |t| noise unrelated to the constant-time tag
// compare this bench is meant to verify.
//
// A naive byte-by-byte tag compare would return at the first differing
// byte, producing a massive t-statistic. The implementation delegates to
// `subtle::ConstantTimeEq`, which is content-independent.
// -----------------------------------------------------------------------------
fn bench_verify_hmac_sha256(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let message = b"latticearc dudect probe message".to_vec();
    let valid_tag = hmac_sha256(&key, &message).expect("hmac");
    let mut tampered_tag = valid_tag;
    tampered_tag[0] ^= 0xFF;

    let verifier = HmacSha256Verifier::new(&key).expect("verifier");

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
            let _ = verifier.verify(&message, &tag);
        });
    }
}

ctbench_main!(bench_verify_hmac_sha256);
