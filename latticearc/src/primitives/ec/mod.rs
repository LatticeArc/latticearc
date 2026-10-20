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
//! - **P-256 / P-384**: ECDSA verification only ([`p256`], [`p384`]), for
//!   interoperability with third-party signed formats (JWS `ES256`/`ES384`,
//!   COSE, X.509 chains); backed by aws-lc-rs
//!
//! [`hash_to_curve`] provides the RFC 9380 suite `P256_XMD:SHA-256_SSWU_RO_`.
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

/// Shared aws-lc-rs ECDSA verification core behind [`p256`] and [`p384`].
mod nist_ecdsa;

/// ECDSA P-256 / SHA-256 signature verification (FIPS 186-5), verify only.
pub mod p256;

/// ECDSA P-384 / SHA-384 signature verification (FIPS 186-5), verify only.
pub mod p384;

/// RFC 9380 hash-to-curve for P-256 (`P256_XMD:SHA-256_SSWU_RO_`).
///
/// Not a FIPS-approved algorithm; compiled in both builds, like [`ed25519`].
pub mod hash_to_curve;

// Re-exports (non-FIPS curves only)
#[cfg(not(feature = "fips"))]
pub use secp256k1::*;

// Ed25519 re-exports are always available so downstream modules (hybrid,
// unified_api::convenience) can delegate to the primitives wrapper without
// duplicating feature gates.
pub use ed25519::*;

// The P-curve verifiers and hash-to-curve are re-exported by name, not by
// glob, so their public surface stays an explicit list.
pub use hash_to_curve::{H2C_MAX_DST_LEN, P256_H2C_OUTPUT_LEN, p256_xmd_sha256_sswu_ro};
pub use p256::{
    P256_DIGEST_LEN, P256_FIXED_SIGNATURE_LEN, P256_MAX_DER_SIGNATURE_LEN, P256_PUBLIC_KEY_LEN,
    verify_ecdsa_p256_sha256, verify_ecdsa_p256_sha256_fixed, verify_ecdsa_p256_sha256_prehash,
    verify_ecdsa_p256_sha256_prehash_fixed,
};
pub use p384::{
    P384_DIGEST_LEN, P384_FIXED_SIGNATURE_LEN, P384_MAX_DER_SIGNATURE_LEN, P384_PUBLIC_KEY_LEN,
    verify_ecdsa_p384_sha384, verify_ecdsa_p384_sha384_fixed, verify_ecdsa_p384_sha384_prehash,
    verify_ecdsa_p384_sha384_prehash_fixed,
};

// Traits are always available
pub use traits::{EcKeyPair, EcSignature};
