//! DudeCT statistical constant-time harness.
//!
//! Runs Welch's t-test across two input classes for:
//!
//! - `HmacSha256Verifier::verify`, which touches aws-lc-rs FFI that
//!   Valgrind-memcheck cannot cleanly reason about;
//! - the secret-input paths a key-derivation pipeline typically chains:
//!   RFC 9380 hash-to-curve on P-256 with a secret message, Argon2id and
//!   HKDF with a secret input, `primitives::ct::ct_eq_array`, and the
//!   AES-256-GCM tag check.
//!
//! A large `|t|` (conventionally > 5) is strong statistical evidence that
//! the operation's runtime depends on secret data — i.e., a timing side
//! channel. Small `|t|` is *not* a proof of constant-timeness (the chosen
//! input distribution might not exercise the leak), but it's the standard
//! empirical check used by the crypto literature since Reparaz et al.'s
//! DudeCT paper (2016/1123). A result holds only for the CPU, compiler and
//! dependency versions it was measured on, and wall-clock timing does not
//! observe cache-line or other microarchitectural channels.
//!
//! Pure-Rust paths (including `HybridKemSecretKey::ct_eq`) are verified
//! by `tests/examples/ctgrind_ct.rs` under Valgrind memcheck instead —
//! that gives a deterministic instruction-level oracle without the
//! shared-runner statistical noise dudect is sensitive to.
//!
//! Invoke via:
//!     cargo run --release --example dudect_ct -p latticearc-tests
//!
//! Run one bench with `-- --filter <substring>` (for example
//! `-- --filter h2c`).
//!
//! Output format (per bench):
//!     bench <name> ... : n == +X.XXXM, max t = +Y.YYYYY, max tau = ...
//!
//! The `.github/workflows/dudect.yml` workflow parses `max t` and fails if
//! any bench produces `|max t| > DUDECT_T_THRESHOLD` (default 10 —
//! conservative vs. the paper's 5 to absorb shared-runner noise).

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::hint::black_box;

use dudect_bencher::rand::{Rng, RngExt};
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};

use latticearc::primitives::aead::AeadCipher;
use latticearc::primitives::aead::aes_gcm::AesGcm256;
use latticearc::primitives::ct::ct_eq_array;
use latticearc::primitives::ec::p256_xmd_sha256_sswu_ro;
use latticearc::primitives::kdf::{Argon2Params, argon2id, hkdf_with_context};
use latticearc::primitives::mac::hmac::{HmacSha256Verifier, hmac_sha256};

const SAMPLES: usize = 100_000;

/// Argon2id is far slower per call than the other paths, so it gets fewer
/// samples.
const ARGON2_SAMPLES: usize = 20_000;

/// Calls per measured sample for operations that finish in a few timer
/// ticks or less. The timer behind `std::time::Instant` ticks at about 42 ns on
/// Apple Silicon, so a single 32-byte compare would round to 0 or 1 tick.
const FAST_OP_REPEAT: usize = 64;

/// RFC 9380 Appendix J.1.1 suite DST. Only its length matters for timing,
/// and it is public.
const H2C_DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

/// Pick the class of one sample at random, as the DudeCT paper does, so that
/// drift over the run cannot line up with one class.
fn random_class(rng: &mut BenchRng) -> Class {
    if rng.random::<bool>() { Class::Left } else { Class::Right }
}

/// Fix-vs-random inputs: Left samples use `fixed`, Right samples a fresh
/// random value. Inputs are drawn before timing starts.
fn fix_vs_random<const N: usize>(
    rng: &mut BenchRng,
    fixed: [u8; N],
    samples: usize,
) -> Vec<([u8; N], Class)> {
    let mut inputs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let class = random_class(rng);
        let input = match class {
            Class::Left => fixed,
            Class::Right => {
                let mut v = [0u8; N];
                rng.fill_bytes(&mut v);
                v
            }
        };
        inputs.push((input, class));
    }
    inputs
}

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

// -----------------------------------------------------------------------------
// `p256_xmd_sha256_sswu_ro` with a secret 32-byte message (fix vs random).
//
// Left:  the all-zero message
// Right: a fresh random message
//
// The message and DST lengths are fixed, so `expand_message_xmd` does the
// same number of SHA-256 blocks for both classes; any difference comes from
// the field arithmetic of `hash_to_field`, the simplified SWU map (square
// root and `is_square`), point addition, or the affine conversion.
// -----------------------------------------------------------------------------
fn bench_h2c_p256_secret_msg(runner: &mut CtRunner, rng: &mut BenchRng) {
    for (msg, class) in fix_vs_random(rng, [0u8; 32], SAMPLES) {
        runner.run_one(class, || p256_xmd_sha256_sswu_ro(black_box(&msg), H2C_DST));
    }
}

// -----------------------------------------------------------------------------
// `ct_eq_array` on 32-byte values: equal vs first byte differs.
//
// Left:  a == b
// Right: a and b differ in byte 0 (an early-exit compare returns at once)
//
// The secret operand is random per sample; each sample times
// `FAST_OP_REPEAT` compares.
// -----------------------------------------------------------------------------
fn bench_ct_eq_array_32(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<([u8; 32], [u8; 32], Class)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let class = random_class(rng);
        let mut a = [0u8; 32];
        rng.fill_bytes(&mut a);
        let mut b = a;
        if matches!(class, Class::Right) {
            b[0] ^= 0x01;
        }
        inputs.push((a, b, class));
    }

    for (a, b, class) in inputs {
        runner.run_one(class, || {
            for _ in 0..FAST_OP_REPEAT {
                black_box(ct_eq_array(black_box(&a), black_box(&b)));
            }
        });
    }
}

// -----------------------------------------------------------------------------
// AES-256-GCM tag check: where the first wrong tag byte sits.
//
// Left:  tag byte 0 flipped
// Right: tag byte 15 flipped
//
// Both classes fail authentication, so the success path (plaintext copy)
// is not part of the comparison. An early-exit tag compare would reject the
// Left class sooner.
// -----------------------------------------------------------------------------
fn bench_aes256gcm_tag_check(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    let cipher = AesGcm256::new(&key).expect("aes-gcm key");
    let nonce = [0x24u8; 12];
    let plaintext = [0x5Au8; 64];
    let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).expect("encrypt");

    let mut first = tag;
    first[0] ^= 0x01;
    let mut last = tag;
    last[15] ^= 0x01;

    let mut inputs: Vec<([u8; 16], Class)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let class = random_class(rng);
        let t = if matches!(class, Class::Left) { first } else { last };
        inputs.push((t, class));
    }

    // One decrypt takes only a few timer ticks, so each sample times
    // `FAST_OP_REPEAT` of them.
    for (t, class) in inputs {
        runner.run_one(class, || {
            for _ in 0..FAST_OP_REPEAT {
                black_box(cipher.decrypt(&nonce, &ciphertext, black_box(&t), None).is_err());
            }
        });
    }
}

// -----------------------------------------------------------------------------
// `hkdf_with_context` with secret 32-byte IKM (fix vs random).
//
// Left:  the all-zero IKM
// Right: a fresh random IKM
//
// Salt, context and output length are fixed and public.
// -----------------------------------------------------------------------------
fn bench_hkdf_secret_ikm(runner: &mut CtRunner, rng: &mut BenchRng) {
    let salt = [0x11u8; 32];
    for (ikm, class) in fix_vs_random(rng, [0u8; 32], SAMPLES) {
        runner.run_one(class, || {
            hkdf_with_context(black_box(&ikm), Some(&salt), b"dudect/hkdf", 32)
                .map(|r| r.key_length())
        });
    }
}

// -----------------------------------------------------------------------------
// `argon2id` with a secret 16-byte password (fix vs random).
//
// Left:  the all-zero password
// Right: a fresh random password
//
// Runs at a reduced cost (64 KiB, 1 pass, 1 lane) so enough samples fit in
// a short run; deployment costs are much larger. Argon2id's second half of
// the first pass uses data-dependent memory addressing by design (RFC 9106
// §3.4), which is a cache-timing property that wall-clock dudect does not
// observe.
// -----------------------------------------------------------------------------
fn bench_argon2id_secret_password(runner: &mut CtRunner, rng: &mut BenchRng) {
    let params = Argon2Params::new(64, 1, 1, 32).expect("argon2 params");
    let salt = [0x33u8; 16];
    for (password, class) in fix_vs_random(rng, [0u8; 16], ARGON2_SAMPLES) {
        runner.run_one(class, || {
            argon2id(black_box(&password), &salt, &params).map(|r| r.key_length())
        });
    }
}

ctbench_main!(
    bench_verify_hmac_sha256,
    bench_h2c_p256_secret_msg,
    bench_ct_eq_array_32,
    bench_aes256gcm_tag_check,
    bench_hkdf_secret_ikm,
    bench_argon2id_secret_password
);
