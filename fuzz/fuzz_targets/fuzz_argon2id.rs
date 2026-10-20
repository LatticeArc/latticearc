#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for Argon2id key derivation
//!
//! Drives `argon2id` with fuzzer-chosen password, salt and cost parameters.
//! Checks that every input either returns an error or a key of the requested
//! length, that derivation is deterministic, and that the salt changes the
//! output. Memory is capped at 64 KiB and passes at 4 so each run stays fast.
//! The reduced ranges straddle the validator's lower bounds (zero memory,
//! passes, lanes and output length are all reachable), so both the rejection
//! and the success paths run.

use latticearc::primitives::kdf::argon2id::{Argon2Params, argon2id};
use libfuzzer_sys::fuzz_target;
use subtle::ConstantTimeEq;

/// Memory cap for the harness, in KiB.
const MAX_FUZZ_MEMORY_KIB: u32 = 64;
/// Pass cap for the harness.
const MAX_FUZZ_ITERATIONS: u32 = 4;

fuzz_target!(|data: &[u8]| {
    // Layout: [mem, iter, par, out_len, salt_len, ...salt, ...password]
    let Some((header, rest)) = data.split_first_chunk::<5>() else {
        return;
    };
    let [mem, iter, par, out_len, salt_len] = *header;

    let salt_len = usize::from(salt_len % 33);
    let Some((salt, password)) = rest.split_at_checked(salt_len.min(rest.len())) else {
        return;
    };

    // Small parameters that may or may not be valid: memory 0..=64 KiB,
    // passes 0..=4, lanes 0..=8, output 0..=127 bytes.
    let params = Argon2Params {
        memory_kib: u32::from(mem) % (MAX_FUZZ_MEMORY_KIB + 1),
        iterations: u32::from(iter) % (MAX_FUZZ_ITERATIONS + 1),
        parallelism: u32::from(par % 9),
        output_len: usize::from(out_len % 128),
    };

    let Ok(result) = argon2id(password, salt, &params) else {
        // Rejection must be consistent with the validator or input policy.
        let valid_params = params.validate().is_ok();
        let valid_inputs = !password.is_empty()
            && salt.len() >= Argon2Params::MIN_SALT_LEN
            && salt.iter().any(|&b| b != 0);
        assert!(!(valid_params && valid_inputs), "valid inputs must derive a key");
        return;
    };

    assert!(params.validate().is_ok(), "accepted params must validate");
    assert_eq!(result.expose_secret().len(), params.output_len);
    assert_eq!(result.params(), &params);

    let again = argon2id(password, salt, &params).expect("second derivation must succeed");
    assert!(bool::from(result.ct_eq(&again)), "Argon2id must be deterministic");

    // Flip one salt byte (keep it non-zero overall) and expect a new key.
    let mut other_salt = salt.to_vec();
    if let Some(first) = other_salt.first_mut() {
        *first = first.wrapping_add(1);
    }
    if other_salt.iter().any(|&b| b != 0) {
        if let Ok(other) = argon2id(password, &other_salt, &params) {
            assert!(!bool::from(result.ct_eq(&other)), "salt must change the output");
        }
    }
});
