#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Formal verification framework for TLS security properties
//!
//! This module provides formal verification of critical TLS security paths
//! using Kani model checking, property-based testing, and SAW cryptographic proofs.

pub mod invariants;
#[cfg(feature = "kani")]
pub mod kani;
pub mod security_properties;

#[cfg(feature = "formal_verification")]
pub mod property_based;

#[cfg(feature = "saw")]
pub mod saw_proofs;

#[cfg(feature = "formal_verification")]
pub use property_based::*;

pub use invariants::*;
pub use security_properties::*;
