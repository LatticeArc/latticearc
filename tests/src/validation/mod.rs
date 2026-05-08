#![allow(unused_imports)]

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
pub mod nist_kat;
pub mod nist_sp800_22;
pub mod output;
pub mod proptest_crypto;
pub mod resource_limits;
pub mod rfc_vectors;
pub mod timing;
pub mod validation_summary;
pub mod wycheproof;

// Re-exports
#[expect(
    ambiguous_glob_reexports,
    reason = "intentional re-export pattern; later items shadow earlier ones"
)]
pub use bounds::*;
#[expect(
    ambiguous_glob_reexports,
    reason = "intentional re-export pattern; later items shadow earlier ones"
)]
pub use cavp::*;
pub use fips_validation::*;
pub use format::*;
pub use input::*;
pub use kat_tests::*;
pub use output::*;
pub use resource_limits::*;
pub use timing::*;
