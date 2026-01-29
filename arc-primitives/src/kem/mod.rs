#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Key Encapsulation Mechanisms (KEM)
//!
//! This module provides a unified interface for both post-quantum and classical
//! key encapsulation mechanisms. It supports the following algorithms:
//!
//! ## Post-Quantum Algorithms
//!
//! - **ML-KEM (FIPS 203)**: Module-Lattice-Based Key Encapsulation Mechanism
//!   - ML-KEM-512: NIST Security Category 1 (AES-128 equivalent)
//!   - ML-KEM-768: NIST Security Category 3 (AES-192 equivalent)
//!   - ML-KEM-1024: NIST Security Category 5 (AES-256 equivalent)
//!
//! ## Classical Algorithms
//!
//! - **ECDH (X25519)**: Elliptic Curve Diffie-Hellman key exchange (RFC 7748)
//!
//! ## Security Properties
//!
//! All KEM implementations in this module provide:
//! - **IND-CCA2**: Indistinguishability under adaptive Chosen-Ciphertext Attack
//! - **Constant-time**: All secret-handling operations execute in constant time
//! - **Zeroization**: Secret keys are securely wiped when dropped
//!
//! ## Example Usage
//!
//! ### ML-KEM Key Encapsulation
//!
//! ```no_run
//! use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
//! use rand::rngs::OsRng;
//!
//! // Generate keypair
//! let mut rng = OsRng;
//! let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;
//!
//! // Encapsulate shared secret
//! let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &pk)?;
//!
//! // Decapsulate shared secret
//! let recovered_secret = MlKem::decapsulate(&sk, &ciphertext)?;
//! assert_eq!(shared_secret, recovered_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Mathematical Correctness
//!
//! The ML-KEM implementation is based on the Module-LWE (Learning with Errors)
//! hardness problem, which provides provable quantum resistance. The security
//! reduction ensures that breaking ML-KEM requires solving the Module-LWE problem,
//! which is believed to be hard even for quantum computers.
//!
//! ## Module Structure
//!
//! - [`ml_kem`]: ML-KEM (FIPS 203) post-quantum KEM
//! - [`ecdh`]: Classical elliptic curve Diffie-Hellman (X25519)

pub mod ecdh;
pub mod ml_kem;

// Re-exports for convenience
pub use ecdh::*;
pub use ml_kem::*;
