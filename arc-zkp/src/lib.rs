#![doc = "Basic Zero-Knowledge Proof Primitives"]
//!
//! # arc-zkp
//!
//! Basic zero-knowledge proof primitives for LatticeArc. This crate provides
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
//! use arc_zkp::schnorr::{SchnorrProver, SchnorrVerifier};
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
//! For advanced ZKP (zk-SNARKs, zk-STARKs, complex circuits), see
//! `arc-enterprise-zkp` in the enterprise offering.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

pub mod commitment;
pub mod error;
pub mod schnorr;
pub mod sigma;

pub use commitment::{HashCommitment, HashOpening, PedersenCommitment, PedersenOpening};
pub use error::{Result, ZkpError};
pub use schnorr::{SchnorrProof, SchnorrProver, SchnorrVerifier};
pub use sigma::{DlogEqualityProof, DlogEqualityStatement, FiatShamir, SigmaProof, SigmaProtocol};
