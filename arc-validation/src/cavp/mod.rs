#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(unused_imports, ambiguous_glob_reexports)]

//! CAVP (Cryptographic Algorithm Validation Program) test framework
//!
//! This module provides comprehensive NIST CAVP testing including:
//! - Official test vector loading and validation
//! - Algorithm-specific test runners
//! - Compliance reporting and documentation
//! - Embedded NIST CAVP test vectors for algorithm certification

pub mod compliance;
pub mod documentation;
pub mod enhanced_framework;
pub mod integration_tests;
pub mod official_vectors;
pub mod pipeline;
pub mod simple_tests;
pub mod storage;
#[cfg(test)]
pub mod tests;
pub mod types;
pub mod vectors;

pub use compliance::*;
pub use enhanced_framework::{
    CavpTestExecutor as EnhancedCavpTestExecutor, PipelineConfig as EnhancedPipelineConfig, *,
};
pub use official_vectors::*;
pub use pipeline::*;
pub use storage::*;
pub use types::*;
pub use vectors::*;
