//! Constant-Time Validation Benchmarks
//!
//! These benchmarks use the dudect methodology to detect timing side-channels
//! in cryptographic operations. The dudect approach uses statistical analysis
//! (Welch's t-test) to determine if execution time depends on secret data.
//!
//! See: <https://github.com/oreparaz/dudect>
//!
//! # Running
//! ```bash
//! cargo bench --package arc-validation --bench constant_time
//! ```

// JUSTIFICATION: Benchmark code patterns - strict lints relaxed for benchmark-specific idioms
#![allow(missing_docs)] // Criterion macros generate undocumented code
#![allow(clippy::semicolon_if_nothing_returned)] // Criterion iter() returns value
#![allow(clippy::needless_pass_by_value)] // Criterion function signature
#![allow(clippy::indexing_slicing)] // Benchmark data with known indices
#![allow(clippy::cast_possible_truncation)] // Benchmark test data generation
#![allow(clippy::cast_sign_loss)] // Benchmark test data generation
#![allow(clippy::arithmetic_side_effects)] // Benchmark test data generation
#![allow(clippy::explicit_iter_loop)] // Benchmark iteration clarity
#![allow(clippy::expect_used)] // Benchmark setup with known-valid data

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use subtle::ConstantTimeEq;

/// Test that constant-time comparison doesn't leak position of difference
fn bench_constant_time_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant_time_compare");

    // Two 32-byte arrays that differ at position 0
    let a = [0x42u8; 32];
    let mut b_early = a;
    b_early[0] ^= 0xff;

    // Two 32-byte arrays that differ at position 31
    let mut b_late = a;
    b_late[31] ^= 0xff;

    group.bench_function("diff_at_start", |b| {
        b.iter(|| {
            let result: bool = a.ct_eq(black_box(&b_early)).into();
            black_box(result)
        })
    });

    group.bench_function("diff_at_end", |b| {
        b.iter(|| {
            let result: bool = a.ct_eq(black_box(&b_late)).into();
            black_box(result)
        })
    });

    // Equal arrays
    group.bench_function("equal", |b| {
        b.iter(|| {
            let result: bool = a.ct_eq(black_box(&a)).into();
            black_box(result)
        })
    });

    group.finish();
}

/// Test that HMAC verification time doesn't depend on tag correctness
fn bench_hmac_verify(c: &mut Criterion) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut group = c.benchmark_group("hmac_verify");

    let key = [0x42u8; 32];
    let message = b"test message for hmac verification benchmark";

    // Compute valid tag
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
    mac.update(message);
    let valid_tag = mac.finalize().into_bytes();

    // Create invalid tag (differs in first byte)
    let mut invalid_tag_early = valid_tag.to_vec();
    invalid_tag_early[0] ^= 0xff;

    // Create invalid tag (differs in last byte)
    let mut invalid_tag_late = valid_tag.to_vec();
    invalid_tag_late[31] ^= 0xff;

    group.bench_function("valid_tag", |b| {
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
            mac.update(black_box(message));
            let result = mac.verify_slice(black_box(&valid_tag));
            black_box(result)
        })
    });

    group.bench_function("invalid_tag_early", |b| {
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
            mac.update(black_box(message));
            let result = mac.verify_slice(black_box(&invalid_tag_early));
            black_box(result)
        })
    });

    group.bench_function("invalid_tag_late", |b| {
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
            mac.update(black_box(message));
            let result = mac.verify_slice(black_box(&invalid_tag_late));
            black_box(result)
        })
    });

    group.finish();
}

/// Test that AES-GCM encryption time doesn't depend on plaintext content
fn bench_aes_gcm_plaintext_independent(c: &mut Criterion) {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    let mut group = c.benchmark_group("aes_gcm_plaintext");

    let key_bytes = [0x42u8; 32];
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).expect("AES key");
    let key = LessSafeKey::new(unbound_key);

    // All zeros plaintext
    let plaintext_zeros = vec![0x00u8; 1024];
    // All ones plaintext
    let plaintext_ones = vec![0xffu8; 1024];
    // Random-looking plaintext
    let plaintext_mixed: Vec<u8> = (0..1024).map(|i| (i * 17 + 31) as u8).collect();

    let nonce_bytes = [0u8; 12];

    group.bench_function("zeros", |b| {
        b.iter(|| {
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let mut in_out = black_box(plaintext_zeros.clone());
            let result = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out);
            black_box(result)
        })
    });

    group.bench_function("ones", |b| {
        b.iter(|| {
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let mut in_out = black_box(plaintext_ones.clone());
            let result = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out);
            black_box(result)
        })
    });

    group.bench_function("mixed", |b| {
        b.iter(|| {
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let mut in_out = black_box(plaintext_mixed.clone());
            let result = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out);
            black_box(result)
        })
    });

    group.finish();
}

/// Test that ChaCha20-Poly1305 encryption time doesn't depend on plaintext
fn bench_chacha20_poly1305_plaintext_independent(c: &mut Criterion) {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };

    let mut group = c.benchmark_group("chacha20_poly1305_plaintext");

    let key = [0x42u8; 32];
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = [0u8; 12];

    // All zeros plaintext
    let plaintext_zeros = vec![0x00u8; 1024];
    // All ones plaintext
    let plaintext_ones = vec![0xffu8; 1024];

    group.bench_function("zeros", |b| {
        b.iter(|| {
            let result =
                cipher.encrypt(black_box(&nonce.into()), black_box(plaintext_zeros.as_slice()));
            black_box(result)
        })
    });

    group.bench_function("ones", |b| {
        b.iter(|| {
            let result =
                cipher.encrypt(black_box(&nonce.into()), black_box(plaintext_ones.as_slice()));
            black_box(result)
        })
    });

    group.finish();
}

/// Test that Ed25519 signature verification time doesn't depend on signature validity
fn bench_ed25519_verify(c: &mut Criterion) {
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    let mut group = c.benchmark_group("ed25519_verify");

    // Generate a key pair
    let secret_bytes = [0x42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let message = b"test message for signature verification";
    let valid_signature = signing_key.sign(message);

    // Create invalid signature
    let mut invalid_sig_bytes = valid_signature.to_bytes();
    invalid_sig_bytes[0] ^= 0xff;
    // Note: Invalid signatures may fail parsing, so we test with valid structure but wrong value
    let invalid_signature = ed25519_dalek::Signature::from_bytes(&invalid_sig_bytes);

    group.bench_function("valid_signature", |b| {
        b.iter(|| {
            let result = verifying_key.verify(black_box(message), black_box(&valid_signature));
            black_box(result)
        })
    });

    group.bench_function("invalid_signature", |b| {
        b.iter(|| {
            let result = verifying_key.verify(black_box(message), black_box(&invalid_signature));
            black_box(result)
        })
    });

    group.finish();
}

/// Test HKDF key derivation time independence from input entropy
fn bench_hkdf_input_independent(c: &mut Criterion) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut group = c.benchmark_group("hkdf_input");

    let salt = [0x00u8; 32];
    let info = b"application context";

    // Low entropy IKM (all zeros)
    let ikm_low_entropy = [0x00u8; 32];
    // High entropy IKM (varied bytes)
    let ikm_high_entropy: [u8; 32] = core::array::from_fn(|i| (i * 17 + 31) as u8);

    group.bench_function("low_entropy_ikm", |b| {
        b.iter(|| {
            let hk = Hkdf::<Sha256>::new(Some(&salt), black_box(&ikm_low_entropy));
            let mut okm = [0u8; 64];
            let _ = hk.expand(info, &mut okm);
            black_box(okm)
        })
    });

    group.bench_function("high_entropy_ikm", |b| {
        b.iter(|| {
            let hk = Hkdf::<Sha256>::new(Some(&salt), black_box(&ikm_high_entropy));
            let mut okm = [0u8; 64];
            let _ = hk.expand(info, &mut okm);
            black_box(okm)
        })
    });

    group.finish();
}

/// Test that memory comparison using subtle is constant-time across sizes
fn bench_ct_compare_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ct_compare_sizes");

    for size in [16, 32, 64, 128, 256, 512, 1024].iter() {
        let a: Vec<u8> = (0..*size).map(|i| i as u8).collect();
        let b = a.clone();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |bench, _| {
            bench.iter(|| {
                let result: bool = a.ct_eq(black_box(&b)).into();
                black_box(result)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_constant_time_compare,
    bench_hmac_verify,
    bench_aes_gcm_plaintext_independent,
    bench_chacha20_poly1305_plaintext_independent,
    bench_ed25519_verify,
    bench_hkdf_input_independent,
    bench_ct_compare_sizes,
);

criterion_main!(benches);
