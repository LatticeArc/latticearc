#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hash Functions
//!
//! Cryptographic hash functions (SHA2, SHA3).

pub mod sha2;
pub mod sha3;

pub use sha2::*;
pub use sha3::*;
