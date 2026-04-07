#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Elliptic Curve Cryptography
//!
//! Classical elliptic curve implementations for signatures.
//!
//! ## Supported Curves
//!
//! - **secp256k1**: 128-bit security, widely used in cryptocurrencies
//! - **Ed25519**: 128-bit security, high performance, RFC 8032 compliant
//!
//! ## Unified API Design
//!
//! All elliptic curve operations follow a consistent trait-based API:
//! - `EcSignature` trait for signature schemes
//! - `EcKeyPair` trait for key management
//! - Result-based error handling
//! - Zeroize for secure memory wiping

/// Unified elliptic curve traits
pub mod traits;

/// secp256k1 elliptic curve operations. Non-FIPS: not a NIST-approved curve.
#[cfg(not(feature = "fips"))]
pub mod secp256k1;

/// Ed25519 signature operations (RFC 8032).
///
/// Note: Ed25519 is not NIST-approved for FIPS 140-3 signature generation,
/// but the wrapper module is compiled in both FIPS and non-FIPS builds so
/// higher layers (convenience API, hybrid signatures) can route all Ed25519
/// operations through a single primitives entry point. Callers that need
/// FIPS-approved signatures must use ML-DSA or SLH-DSA instead.
pub mod ed25519;

// Re-exports (non-FIPS curves only)
#[cfg(not(feature = "fips"))]
pub use secp256k1::*;

// Ed25519 re-exports are always available so downstream modules (hybrid,
// unified_api::convenience) can delegate to the primitives wrapper without
// duplicating feature gates.
pub use ed25519::*;

// Traits are always available
pub use traits::{EcKeyPair, EcSignature};
