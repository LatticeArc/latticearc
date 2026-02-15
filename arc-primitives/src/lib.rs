#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Glob re-exports are intentional for module convenience API.
// This allows `use arc_primitives::*` to bring in all public types.
// Specific type exports below provide explicit access when disambiguation is needed.
#![allow(ambiguous_glob_reexports)]

//! # LatticeArc Primitives
//!
//! Core cryptographic primitives for LatticeArc including post-quantum and classical algorithms.
//!
//! All algorithms are always available. Algorithm selection is handled at runtime via
//! `arc-core`'s auto/context-based selection based on security requirements and hardware
//! capabilities.
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
//! - **sig::fndsa**: FN-DSA (FIPS 206) Lattice Signatures via `fn-dsa` crate
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
//! | ML-DSA | `fips204` crate | No (awaiting aws-lc-rs API) |
//! | SLH-DSA | `fips205` crate | Audited |
//! | FN-DSA | `fn-dsa` crate | Partial |
//! | AES-GCM | `aws-lc-rs` | Yes |
//! | SHA-2/3 | `sha2`/`sha3` | Audited |
//!
//! See `docs/FIPS_CERTIFICATION_PATH.md` for full compliance roadmap.

// Core cryptographic modules
pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod mac;
pub mod rand;
pub mod security;
pub mod sig;

// Supporting modules
pub mod ec;
pub mod error;
pub mod fips_error;

// Non-FIPS modules: NTT polynomial arithmetic is not part of the FIPS module boundary.
#[cfg(not(feature = "fips"))]
pub mod polynomial;

// FIPS 140-3 Self-Test Module
#[cfg(feature = "fips-self-test")]
pub mod self_test;

// FIPS 140-3 Pairwise Consistency Test Module
pub mod pct;

#[cfg(test)]
mod zeroization_tests;

#[cfg(test)]
mod simple_zeroization_tests;

pub use aead::*;
pub use hash::*;
pub use kdf::*;
pub use kem::*;
pub use keys::*;
pub use mac::*;
pub use rand::*;
pub use sig::*;

// Explicit PQ type exports for unified API
pub use sig::{
    fndsa::{
        KeyPair as FnDsaKeyPair, Signature as FnDsaSignature, SigningKey as FnDsaSigningKey,
        VerifyingKey as FnDsaVerifyingKey,
    },
    ml_dsa::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature},
    slh_dsa::{SigningKey as SlhDsaSigningKey, VerifyingKey as SlhDsaVerifyingKey},
};
