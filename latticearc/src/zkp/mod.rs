#![doc = "Basic Zero-Knowledge Proof Primitives"]
//!
//! # Zero-Knowledge Proofs
//!
//! Basic zero-knowledge proof primitives for LatticeArc. This module provides
//! foundational ZKP building blocks that can be used for authentication,
//! verification, and simple proof systems.
//!
//! ## Features
//!
//! - **Schnorr Proofs**: Prove knowledge of a discrete logarithm
//! - **Pedersen Commitments**: Hiding and binding commitments
//! - **Sigma Protocols**: Basic interactive proofs (Fiat-Shamir transformed)
//! - **Hash Commitments**: Simple hash-based commitments
//!
//! ## Example
//!
//! ```
//! use latticearc::zkp::schnorr::{SchnorrProver, SchnorrVerifier};
//!
//! // Prover demonstrates knowledge of secret key
//! let (prover, public_key) = SchnorrProver::new().unwrap();
//! let proof = prover.prove(b"challenge context").unwrap();
//!
//! // Verifier checks proof without learning the secret
//! let verifier = SchnorrVerifier::new(public_key);
//! assert!(verifier.verify(&proof, b"challenge context").unwrap());
//! ```
//!
//! ## Security
//!
//! These are basic primitives suitable for:
//! - Authentication (prove identity without revealing secrets)
//! - Simple commitments (commit to a value, reveal later)
//! - Basic sigma protocols
//!
//! For advanced ZKP (zk-SNARKs, zk-STARKs, complex circuits), external
//! crates are recommended.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Commitment schemes (Pedersen, hash-based).
pub mod commitment;
/// Error types for zero-knowledge proof operations.
pub mod error;
/// Schnorr proof system for discrete-log knowledge proofs.
pub mod schnorr;
/// Sigma protocols and Fiat-Shamir transform.
pub mod sigma;

pub use commitment::{HashCommitment, HashOpening, PedersenCommitment, PedersenOpening};
pub use error::{Result, ZkpError};
pub use schnorr::{SchnorrProof, SchnorrProver, SchnorrVerifier};
pub use sigma::{DlogEqualityProof, DlogEqualityStatement, FiatShamir, SigmaProof, SigmaProtocol};
