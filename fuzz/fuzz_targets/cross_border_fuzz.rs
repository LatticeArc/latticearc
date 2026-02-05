#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for hashing operations
//!
//! Tests that hash_data produces consistent results with arbitrary input.
//! (Cross-border compliance features are available in LatticeArc Enterprise)

use libfuzzer_sys::fuzz_target;
use arc_core::hash_data;

fuzz_target!(|data: &[u8]| {
    // Hash the input data
    let hash1 = hash_data(data);
    let hash2 = hash_data(data);

    // Same input should produce same hash (deterministic)
    assert_eq!(hash1, hash2);

    // Hash should be 32 bytes (SHA-256)
    assert_eq!(hash1.len(), 32);

    // Different data should (almost certainly) produce different hash
    if !data.is_empty() {
        let mut modified = data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        let hash3 = hash_data(&modified);
        // This assertion could theoretically fail due to collision,
        // but is astronomically unlikely
        assert_ne!(hash1, hash3);
    }
});
