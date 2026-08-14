#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for `latticearc::unified_api::hash_data` (SHA3-256 wrapper).
//!
//! Renamed from `cross_border_fuzz.rs` in an earlier audit — the prior name claimed
//! coverage of compliance / jurisdictional code paths that this harness has
//! never exercised. The actual surface tested here is the deterministic
//! SHA-256 wrapper. Compliance / cross-border features are in
//! `proprietary_repo` and have their own enterprise harnesses.

use latticearc::unified_api::hash_data;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Hash the input data
    // `hash_data` is fallible only via the FIPS 140-3 §9.6 operational
    // gate, which cannot trip here: this harness never enters the error
    // state, and the fuzz crate does not enable `fips-self-test`, so the
    // gate compiles to a no-op. An Err would be a genuine bug worth a
    // crash.
    let hash1 = hash_data(data).expect("hash_data must not fail");
    let hash2 = hash_data(data).expect("hash_data must not fail");

    // Same input should produce same hash (deterministic)
    assert_eq!(hash1, hash2);

    // Hash should be 32 bytes (SHA3-256)
    assert_eq!(hash1.len(), 32);

    // Different data should (almost certainly) produce different hash
    if !data.is_empty() {
        let mut modified = data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        let hash3 = hash_data(&modified).expect("hash_data must not fail");
        // This assertion could theoretically fail due to collision,
        // but is astronomically unlikely
        assert_ne!(hash1, hash3);
    }
});
