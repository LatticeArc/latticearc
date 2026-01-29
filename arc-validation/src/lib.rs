#![deny(unsafe_code)]
#![allow(missing_docs)]
#![allow(unused_imports)] // Test infrastructure - re-exports may not all be used
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! LatticeArc Validation
//!
//! Input validation and security checks for cryptographic operations.
//!
//! ## Modules
//!
//! - **input**: Input size, format, and range validation
//! - **output**: Output validation and bounds checking
//! - **timing**: Constant-time operations
//! - **bounds**: Bounds checking for security
//! - **format**: Format validation for keys, ciphertexts, etc.

pub mod bounds;
pub mod cavp;
pub mod fips_validation;
pub mod fips_validation_impl;
pub mod format;
pub mod input;
pub mod kat_tests;
pub mod nist_functions;
pub mod nist_sp800_22;
pub mod output;
pub mod proptest_crypto;
pub mod resource_limits;
pub mod rfc_vectors;
pub mod timing;
pub mod validation_summary;
pub mod wycheproof;

// Re-exports
#[allow(ambiguous_glob_reexports)]
pub use bounds::*;
#[allow(ambiguous_glob_reexports)]
pub use cavp::*;
#[allow(ambiguous_glob_reexports)]
pub use fips_validation::*;
pub use format::*;
pub use input::*;
#[allow(ambiguous_glob_reexports)]
pub use kat_tests::*;
#[allow(ambiguous_glob_reexports)]
pub use output::*;
pub use resource_limits::*;
pub use timing::*;
