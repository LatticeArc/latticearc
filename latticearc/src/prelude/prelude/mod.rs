//! LatticeArc Prelude Module
//!
//! Common types, traits, and utilities used throughout LatticeArc.
//! This crate provides the foundation for error handling, security primitives,
//! and domain constants.
//!
//! ## Philosophy Compliance
//!
//! - Comprehensive error handling with recovery mechanisms
//! - Zero unwrap/expect/panic in production code
//! - Result-based error handling throughout
//! - Self-descriptive naming and proper documentation
//! - Advanced testing infrastructure with fuzzing and formal verification

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// CAVP (Cryptographic Algorithm Validation Program) compliance testing.
pub mod cavp_compliance;
/// CI/CD testing framework and automation.
pub mod ci_testing_framework;
/// Domain separation constants for HKDF and cryptographic operations.
pub mod domains;
/// Comprehensive error handling and recovery systems.
pub mod error;

// Re-export common error types
pub use error::{LatticeArcError, Result};
/// Formal verification infrastructure using Kani model checker.
pub mod formal_verification;
/// Memory safety testing and validation utilities.
pub mod memory_safety_testing;
/// Property-based testing using proptest framework.
pub mod property_based_testing;
/// Side-channel timing analysis for cryptographic operations.
pub mod side_channel_analysis;

/// Library version for envelope format.
///
/// This version number is used in serialized cryptographic envelopes
/// to ensure compatibility across different versions of the library.
pub const VERSION: u8 = 1;
