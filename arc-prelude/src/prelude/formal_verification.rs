//! Formal Verification for Prelude Utilities
//!
//! This module provides formal verification capabilities for critical utility functions.
//! Kani formal verification proofs are available in the TLS crate.
//! Use the arc-tls package with kani for formal verification.
//!
//! # Usage
//!
//! To run formal verification:
//! ```bash
//! cargo kani --package arc-tls
//! ```
//!
//! # Requirements
//!
//! - Kani model checker must be installed: `cargo install kani-verifier`
//! - Only supported on Linux x86_64 and macOS aarch64

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Logs instructions for running formal verification.
///
/// This function provides guidance on using the Kani model checker
/// for formal verification of cryptographic operations.
///
/// # Example
///
/// ```rust
/// use arc_prelude::prelude::formal_verification::run_formal_verification;
///
/// run_formal_verification();
/// ```
pub fn run_formal_verification() {
    tracing::info!("Formal verification requires Kani model checker");
    tracing::info!("Install with: cargo install kani-verifier");
    tracing::info!("Run verification with: cargo kani --package arc-tls");
}
