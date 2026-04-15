#![deny(unsafe_code)]
#![no_main]

//! Allocation-bounded DoS fuzz target.
//!
//! Complements `tests/tests/allocation_budgets.rs` — which gates happy-path
//! refactors against silent allocation bloat — by feeding *adversarial*
//! byte sequences to input-parsing entrypoints and asserting each call
//! stays under a hard per-call allocation cap.
//!
//! Threat model: an attacker controls bytes on the wire (JSON blobs,
//! ciphertexts). A single public-API call on that input must not allocate
//! more than `ALLOC_CAP_BYTES`, regardless of whether it returns `Ok` or
//! `Err`. Libraries that read a length field and `Vec::with_capacity(len)`
//! before validating it are the classic memory-DoS pattern; this target
//! panics the fuzzer if latticearc regresses into that shape.

use std::alloc::System;

use latticearc::primitives::aead::AeadCipher;
use latticearc::primitives::aead::aes_gcm::AesGcm256;
use latticearc::primitives::kem::ml_kem::{MlKem, MlKemCiphertext, MlKemSecurityLevel};
use latticearc::{deserialize_encrypted_output, deserialize_keypair};
use libfuzzer_sys::fuzz_target;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// Per-call hard cap on cumulative `bytes_allocated`. 1 MiB is wide enough
// to cover legitimate worst-case paths (aws-lc-rs context setup, ML-KEM-1024
// keygen buffers) and tight enough to flag any attacker-length-controls-
// Vec::with_capacity regression.
const ALLOC_CAP_BYTES: usize = 1024 * 1024;

fn bounded<F: FnOnce() -> R, R>(label: &str, f: F) -> R {
    let reg = Region::new(GLOBAL);
    let out = f();
    let stats = reg.change();
    assert!(
        stats.bytes_allocated <= ALLOC_CAP_BYTES,
        "DoS: {label} allocated {} bytes (cap {ALLOC_CAP_BYTES})",
        stats.bytes_allocated,
    );
    out
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let selector = data[0];
    let rest = &data[1..];

    match selector % 4 {
        // AEAD decrypt on attacker-provided ciphertext + tag.
        0 => {
            if rest.len() < 16 {
                return;
            }
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let Ok(cipher) = AesGcm256::new(&key) else {
                return;
            };
            let (ct, tag_bytes) = rest.split_at(rest.len().saturating_sub(16));
            let mut tag = [0u8; 16];
            tag.copy_from_slice(tag_bytes);
            bounded("aead_decrypt", || {
                let _ = cipher.decrypt(&nonce, ct, &tag, None);
            });
        }

        // ML-KEM decapsulation on attacker-provided ciphertext.
        1 => {
            let (level, ct_size) = match (selector / 4) % 3 {
                0 => (MlKemSecurityLevel::MlKem512, 768),
                1 => (MlKemSecurityLevel::MlKem768, 1088),
                _ => (MlKemSecurityLevel::MlKem1024, 1568),
            };
            if rest.len() < ct_size {
                return;
            }
            let Ok((_, sk)) = MlKem::generate_keypair(level) else {
                return;
            };
            let Ok(ct) = MlKemCiphertext::new(level, rest[..ct_size].to_vec()) else {
                return;
            };
            bounded("ml_kem_decapsulate", || {
                let _ = MlKem::decapsulate(&sk, &ct);
            });
        }

        // EncryptedOutput JSON deserialization.
        2 => {
            let Ok(json) = std::str::from_utf8(rest) else {
                return;
            };
            bounded("encrypted_output_deser", || {
                let _ = deserialize_encrypted_output(json);
            });
        }

        // KeyPair JSON deserialization.
        _ => {
            let Ok(json) = std::str::from_utf8(rest) else {
                return;
            };
            bounded("keypair_deser", || {
                let _ = deserialize_keypair(json);
            });
        }
    }
});
