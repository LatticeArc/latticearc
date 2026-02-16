//! NIST Known Answer Tests (KAT) Integration Test
//!
//! This test file runs comprehensive NIST compliance tests against
//! the LatticeArc cryptographic implementations.

#![allow(clippy::expect_used)]

mod nist_kat;

// Re-run the test suites (individual tests are in nist_kat/ modules)
