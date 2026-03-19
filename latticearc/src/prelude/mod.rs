//! LatticeArc Prelude
//!
//! Common types, traits, and utilities used throughout LatticeArc.
//! Provides error handling, domain constants, and testing infrastructure.
//!
//! # Example
//!
//! ```rust
//! use latticearc::prelude::error::{LatticeArcError, Result};
//!
//! fn example_operation() -> Result<()> {
//!     // Your cryptographic operation here
//!     Ok(())
//! }
//! ```

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
/// Formal verification infrastructure using Kani model checker.
pub mod formal_verification;
/// Memory safety testing and validation utilities.
pub mod memory_safety_testing;
/// Property-based testing using proptest framework.
pub mod property_based_testing;
/// Side-channel timing analysis for cryptographic operations.
pub mod side_channel_analysis;

// Re-export common error types
pub use error::{LatticeArcError, Result};

/// Library version for envelope format.
pub const VERSION: u8 = 1;
