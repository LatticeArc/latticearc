#![deny(unsafe_code)]
#![warn(missing_docs)]
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

/// secp256k1 elliptic curve operations
pub mod secp256k1;

/// Ed25519 signature operations
pub mod ed25519;

// Re-exports
pub use ed25519::*;
pub use secp256k1::*;

// Traits are always available
pub use traits::{EcKeyPair, EcSignature};
