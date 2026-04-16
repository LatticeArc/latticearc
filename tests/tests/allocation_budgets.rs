//! Allocation-budget tests for cryptographic operations.
//!
//! Asserts that public crypto API calls stay under a documented per-call
//! allocation ceiling. Purpose: make memory-DoS via a single API call
//! (OpenSSL CVE-2024-2511 class) representable as a test regression.
//!
//! These are not runtime guards — they run only in test mode, as a
//! regression gate on changes that would silently balloon allocations
//! (e.g., accidental `.to_vec()` on a hot path, redundant `.clone()`s).
//!
//! Budget methodology: budgets are set at ~2× the observed minimum for
//! the operation. That's loose enough to survive minor refactors and
//! tight enough to catch a doubling. When a legitimate refactor pushes
//! the budget, raise the number here and note the reason in the diff.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::alloc::System;

use parking_lot::Mutex;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// `stats_alloc` counters are process-global. When cargo runs test fns in
// parallel, one test's `Region::change()` observes allocations from sibling
// tests, producing flaky failures on tight budgets. Serialize all measured
// regions through this mutex so each assertion sees only its own test's
// allocations.
static MEASURE_LOCK: Mutex<()> = Mutex::new(());

/// Assert that `f` stays below `budget_bytes` in newly allocated bytes and
/// below `budget_allocations` in the number of distinct allocations.
/// Prints the actual values on failure for easy re-calibration.
fn assert_alloc_budget(
    label: &str,
    budget_bytes: usize,
    budget_allocations: usize,
    f: impl FnOnce(),
) {
    let _guard = MEASURE_LOCK.lock();
    let reg = Region::new(GLOBAL);
    f();
    let stats = reg.change();
    // Use `bytes_allocated` (cumulative new bytes, not net) — this is the
    // metric we care about for DoS: total pressure on the allocator.
    assert!(
        stats.bytes_allocated <= budget_bytes,
        "{}: bytes_allocated={} exceeded budget {} ({} allocations)",
        label,
        stats.bytes_allocated,
        budget_bytes,
        stats.allocations,
    );
    assert!(
        stats.allocations <= budget_allocations,
        "{}: allocations={} exceeded budget {} ({} bytes)",
        label,
        stats.allocations,
        budget_allocations,
        stats.bytes_allocated,
    );
}

// =============================================================================
// ML-KEM-768 encapsulate / decapsulate
// =============================================================================

#[test]
fn ml_kem_768_encapsulate_stays_under_budget() {
    use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

    // Pre-generate keys outside the measured region.
    let (pk, _sk) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen must succeed");

    // ML-KEM-768 ciphertext is 1088 B, shared secret is 32 B. Observed ~50 KiB
    // total allocations including the aws-lc-rs context. 100 KiB budget allows
    // ~2× headroom.
    assert_alloc_budget("ml_kem_768_encapsulate", 100 * 1024, 200, || {
        let _out = MlKem::encapsulate(&pk).expect("encap");
    });
}

#[test]
fn ml_kem_768_decapsulate_stays_under_budget() {
    use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

    let (pk, sk) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen must succeed");
    let (_ss_enc, ct) = MlKem::encapsulate(&pk).expect("encap");

    assert_alloc_budget("ml_kem_768_decapsulate", 100 * 1024, 200, || {
        let _ss = MlKem::decapsulate(&sk, &ct).expect("decap");
    });
}

// =============================================================================
// AES-256-GCM encrypt / decrypt of a small payload
// =============================================================================

#[test]
fn aes_256_gcm_encrypt_1kib_stays_under_budget() {
    use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

    let key = [0x42u8; 32];
    let plaintext = vec![0xABu8; 1024];
    let cipher = AesGcm256::new(&key).expect("cipher init");
    let nonce = AesGcm256::generate_nonce();

    // 1 KiB plaintext + AES ctx + zeroizing buffers. Observed ~16 KiB.
    // 32 KiB budget = 2× headroom.
    assert_alloc_budget("aes_256_gcm_encrypt_1kib", 32 * 1024, 200, || {
        let _ct = cipher.encrypt(&nonce, &plaintext, None).expect("encrypt");
    });
}

#[test]
fn aes_256_gcm_decrypt_1kib_stays_under_budget() {
    use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

    let key = [0x42u8; 32];
    let plaintext = vec![0xABu8; 1024];
    let cipher = AesGcm256::new(&key).expect("cipher init");
    let nonce = AesGcm256::generate_nonce();
    let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).expect("encrypt");

    assert_alloc_budget("aes_256_gcm_decrypt_1kib", 32 * 1024, 200, || {
        let _pt = cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decrypt");
    });
}

// =============================================================================
// Hybrid KEM (ML-KEM-768 + X25519) encapsulate
// =============================================================================

#[test]
fn hybrid_kem_768_encapsulate_stays_under_budget() {
    use latticearc::hybrid::kem_hybrid::{encapsulate, generate_keypair};

    let (pk, _sk) = generate_keypair().expect("hybrid keygen");

    // Hybrid encap allocates for: ML-KEM ct, X25519 ephemeral key, KDF output.
    // Observed ~120 KiB. 256 KiB budget.
    assert_alloc_budget("hybrid_kem_768_encapsulate", 256 * 1024, 400, || {
        let _encap = encapsulate(&pk).expect("hybrid encap");
    });
}

// =============================================================================
// HKDF expand to a typical key length
// =============================================================================

#[test]
fn hkdf_sha256_expand_32bytes_stays_under_budget() {
    use latticearc::primitives::kdf::hkdf::hkdf_expand;

    let prk = [0u8; 32];
    let info = b"latticearc allocation test";

    // HKDF-Expand for 32 B output: 1 HMAC round. Observed ~10 KiB on
    // macOS CI after aws-lc-rs 1.16.3 (runtime key-length validation
    // added extra internal buffers). 20 KiB budget = ~2× headroom.
    assert_alloc_budget("hkdf_sha256_expand_32b", 20 * 1024, 50, || {
        let _okm = hkdf_expand(&prk, Some(info), 32).expect("hkdf");
    });
}

// =============================================================================
// HMAC-SHA256 over 1 KiB
// =============================================================================

#[test]
fn hmac_sha256_1kib_stays_under_budget() {
    use latticearc::primitives::mac::hmac::hmac_sha256;

    let key = [0u8; 32];
    let data = vec![0xA5u8; 1024];

    // HMAC over 1 KiB: aws-lc-rs HMAC ctx + 32 B tag. Observed ~4 KiB.
    // 16 KiB budget.
    assert_alloc_budget("hmac_sha256_1kib", 16 * 1024, 100, || {
        let _tag = hmac_sha256(&key, &data).expect("hmac");
    });
}
