#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Cryptographically Secure Random Number Generation
//!
//! Provides CSPRNG implementations and entropy health tests.

pub mod csprng;
pub mod entropy_tests;

// Re-exports
pub use csprng::*;
pub use entropy_tests::{
    frequency_test, repetition_test, run_entropy_health_tests, run_entropy_health_tests_on_bytes,
};
