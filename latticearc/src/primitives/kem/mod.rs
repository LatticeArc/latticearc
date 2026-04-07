#![deny(unsafe_code)]
#![deny(missing_docs)]
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
//! - **ML-KEM** (FIPS 203): **IND-CCA2** — indistinguishability under adaptive
//!   chosen-ciphertext attack. This is a true KEM with an authenticated
//!   ciphertext path; decapsulation rejects invalid ciphertexts.
//! - **X25519 ECDH** (RFC 7748): NOT a CCA-secure KEM on its own. Raw ECDH is
//!   a key-agreement primitive that provides **IND-CPA** (chosen-plaintext
//!   indistinguishability) under the computational Diffie-Hellman assumption,
//!   not IND-CCA2. Within this crate X25519 is only used as an input to the
//!   hybrid HKDF combiner in [`hybrid::kem_hybrid`](crate::hybrid::kem_hybrid),
//!   which upgrades the composed construction to IND-CCA2 via ML-KEM.
//! - **Constant-time** — all secret-handling operations execute in
//!   constant time (delegated to the backing crates `aws-lc-rs` for ML-KEM
//!   and `x25519-dalek` for ECDH).
//! - **Zeroization** — secret keys are scrubbed on drop.
//!
//! ## Example Usage
//!
//! ### ML-KEM Key Encapsulation
//!
//! ```no_run
//! use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
//! use rand::rngs::OsRng;
//!
//! // Generate keypair
//! let mut rng = OsRng;
//! let (pk, sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)?;
//!
//! // Encapsulate shared secret
//! let (shared_secret, ciphertext) = MlKem::encapsulate(&pk)?;
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
