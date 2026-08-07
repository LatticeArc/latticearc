#![deny(missing_docs)]

//! # LatticeArc Primitives
//!
//! Core cryptographic primitives for LatticeArc including post-quantum and classical algorithms.
//!
//! All algorithms are always available. Algorithm selection is handled at runtime via
//! the [`unified_api`](crate::unified_api) auto/context-based selection based on security requirements and hardware
//! capabilities.
//!
//! ## ⚠️ FIPS gate scope (Expert tier)
//!
//! Functions in this module are the **Expert tier** API per
//! `docs/FIPS_SECURITY_POLICY.md` §7. They DO NOT route through
//! `fips_verify_operational()` — the FIPS 140-3 power-up self-test
//! gate fires only at the [`unified_api`](crate::unified_api) entry
//! points (`encrypt`, `decrypt`, `sign_with_key`, `verify`, keygen,
//! hybrid, …). Callers that drop down to `primitives::*` directly in
//! a FIPS deployment MUST invoke
//! `self_test::verify_operational` (feature `fips-self-test` — a doc
//! link cannot resolve across the feature gate) themselves before each session
//! of cryptographic operations to confirm the module is still in the
//! operational state. Skipping the gate produces functionally-correct
//! but uncertified output — sufficient for non-FIPS use,
//! insufficient for a FIPS 140-3 validated boundary.
//!
//! ## Feature Flags
//!
//! - **`fips-self-test`** - Enable FIPS 140-3 power-up self-tests (KAT verification)
//!
//! ## Algorithms
//!
//! ### Post-Quantum (NIST FIPS 203-206)
//!
//! - **kem::ml_kem**: ML-KEM (FIPS 203) Key Encapsulation via `aws-lc-rs`
//! - **sig::ml_dsa**: ML-DSA (FIPS 204) Digital Signatures via `fips204` crate
//! - **sig::slh_dsa**: SLH-DSA (FIPS 205) Hash-based Signatures via `fips205` crate
//! - **sig::fndsa**: FN-DSA (draft FIPS 206) Lattice Signatures via `fn-dsa` crate
//!
//! ### Symmetric Encryption (AEAD)
//!
//! - **aead::aes_gcm**: AES-GCM-128/256 (NIST SP 800-38D) via `aws-lc-rs`
//! - **aead::chacha20poly1305**: ChaCha20-Poly1305 (RFC 8439)
//!
//! ### Hashing
//!
//! - **hash**: SHA-2 (SHA-256, SHA-384, SHA-512) per FIPS 180-4
//! - **hash**: SHA-3 (SHA3-256, SHA3-384, SHA3-512) per FIPS 202
//!
//! ### Key Derivation
//!
//! - **kdf::hkdf**: HKDF (RFC 5869, NIST SP 800-56C)
//! - **kdf::pbkdf2**: PBKDF2 (NIST SP 800-132)
//!
//! ### Classical Cryptography
//!
//! - **kem::ecdh**: X25519 key exchange (RFC 7748)
//! - **ec::ed25519**: Ed25519 signatures (RFC 8032)
//! - **ec::secp256k1**: secp256k1 signatures (Bitcoin/Ethereum compatible)
//!
//! ### Supporting Modules
//!
//! - **keys**: Hybrid keypair management (ML-KEM + X25519)
//! - **rand**: Cryptographically secure random number generation
//! - **mac**: HMAC (FIPS 198-1), CMAC (NIST SP 800-38B)
//! - **security**: Secure memory containers with zeroization
//!
//! ## FIPS 140-3 Compliance Notes
//!
//! | Algorithm | Implementation | FIPS Validated |
//! |-----------|----------------|----------------|
//! | ML-KEM | `aws-lc-rs` | Yes (Cert #4631, #4759, #4816) |
//! | ML-DSA | `fips204` crate | No (aws-lc-rs API not yet stable) |
//! | SLH-DSA | `fips205` crate | No |
//! | FN-DSA | `fn-dsa` crate | No |
//! | AES-GCM | `aws-lc-rs` | Yes |
//! | SHA-2/3 | `sha2`/`sha3` crates | No (RustCrypto, widely reviewed) |
//!
//! See the `docs/` directory for full compliance details.

// Core cryptographic modules
pub mod aead;
pub mod ct;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod mac;
pub mod rand;
pub mod security;
pub mod sig;

// Supporting modules
pub mod ec;
pub mod fips_error;
/// Resource limits for cryptographic operations (DoS prevention).
pub mod resource_limits;

// FIPS 140-3 Self-Test Module
#[cfg(feature = "fips-self-test")]
pub mod self_test;

// FIPS 140-3 Pairwise Consistency Test Module
pub mod pct;

#[cfg(test)]
mod zeroization_tests;

pub use aead::*;
pub use hash::*;
pub use kdf::*;
pub use kem::*;
pub use mac::*;
pub use rand::*;
pub use sig::*;

// Explicit PQ type exports for unified API. Algorithm-prefixed names are
// now the types' own names (see `sig::mod` — the former `SigningKey` /
// `VerifyingKey` collision was resolved by renaming at the source), so
// this is a plain re-export rather than an aliasing one.
pub use sig::{
    fndsa::{FnDsaKeyPair, FnDsaSignature, FnDsaSigningKey, FnDsaVerifyingKey},
    ml_dsa::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature},
    slh_dsa::{SlhDsaSignature, SlhDsaSigningKey, SlhDsaVerifyingKey},
};
