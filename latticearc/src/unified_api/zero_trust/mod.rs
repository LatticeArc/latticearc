#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-trust authentication and access control module.
//!
//! This module provides zero-trust security primitives including zero-knowledge proofs,
//! continuous verification, DID (Decentralized Identifier) support, session management,
//! and access control policies.

mod access;
mod authentication;
mod base;
mod did;
mod primitives;
mod session;

pub use access::*;
pub use authentication::*;
pub use base::*;
pub use did::*;
pub use primitives::*;
pub use session::*;
