//! LatticeArc Prelude
//!
//! Common types, traits, and utilities used throughout LatticeArc.
//! Provides error handling, domain constants, testing infrastructure, AND
//! the most-frequently-used unified-API surface re-exported for ergonomic
//! `use latticearc::prelude::*` consumption.
//!
//! # Example
//!
//! ```rust,no_run
//! use latticearc::prelude::*;
//!
//! // NOTE: `Result` in this prelude is the single-generic alias
//! // `Result<T> = std::result::Result<T, LatticeArcError>` for legacy
//! // callers. New code working against the unified API should use
//! // `std::result::Result<T, CoreError>` directly (aliased as
//! // `StdResult` below to disambiguate).
//! # use std::result::Result as StdResult;
//! # fn example() -> StdResult<(), CoreError> {
//! let config = CryptoConfig::new();
//! let key = vec![0x42u8; 32];
//! let plaintext = b"hello, world";
//! let encrypted = encrypt(plaintext, EncryptKey::Symmetric(&key), config)?;
//! # Ok(())
//! # }
//! ```
//!
//! # What's in this prelude
//!
//! - **Unified API entry points:** `encrypt`, `decrypt`, `sign_with_key`, `verify`,
//!   `generate_signing_keypair`, `generate_hybrid_keypair`.
//! - **Configuration / key types:** `CryptoConfig`, `EncryptKey`, `DecryptKey`,
//!   `SecurityLevel`, `EncryptedOutput`, `SignedData`.
//! - **Error type:** `CoreError` (returned by every API entry point).
//! - **Compatibility re-exports:** `LatticeArcError`, `Result` (the prelude-error
//!   `Result<T> = Result<T, LatticeArcError>` alias for legacy callers; new code
//!   should use `Result<T, CoreError>` directly).
//!
//! Test infrastructure modules (`cavp_compliance`, `formal_verification`, etc.)
//! remain available via explicit `latticearc::prelude::cavp_compliance` paths
//! but are NOT glob-imported, since they're not what user code typically wants.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// CAVP (Cryptographic Algorithm Validation Program) compliance testing.
pub mod cavp_compliance;
/// CI/CD testing framework and automation.
pub mod ci_testing_framework;
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

// Re-export common error types (legacy prelude shape)
pub use error::{LatticeArcError, Result};

// User-facing unified API surface — re-exported so that
// `use latticearc::prelude::*` actually gives you what you want for
// real cryptographic code, not just testing infrastructure.
pub use crate::unified_api::{
    CoreError, CryptoConfig, DecryptKey, EncryptKey, EncryptedOutput, SecurityLevel, SignedData,
    decrypt, encrypt, generate_hybrid_keypair, generate_signing_keypair, sign_with_key, verify,
};

/// Envelope / wire-format version number for serialized cryptographic payloads.
///
/// Distinct from `latticearc::VERSION` (the Cargo package version string).
/// Bumped when the on-disk or over-the-wire serialized format changes in a
/// non-backward-compatible way.
pub const ENVELOPE_FORMAT_VERSION: u8 = 1;
