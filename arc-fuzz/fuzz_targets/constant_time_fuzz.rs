#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for constant-time operations
//!
//! Tests that constant-time comparisons work correctly with arbitrary data.

use libfuzzer_sys::fuzz_target;
use subtle::{Choice, ConstantTimeEq};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Split data into two parts for comparison
    let mid = data.len() / 2;
    let a = &data[..mid];
    let b = &data[mid..];

    // Test constant-time equality
    let ct_result: Choice = a.ct_eq(b);
    let bool_result: bool = ct_result.into();

    // Verify constant-time result matches standard equality
    let expected = a == b;
    assert_eq!(bool_result, expected);

    // Test self-equality
    let self_eq: Choice = a.ct_eq(a);
    assert!(bool::from(self_eq));
});
