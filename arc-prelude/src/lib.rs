//! LatticeArc Prelude Crate
//!
//! This crate provides common types, traits, and utilities used throughout
//! the LatticeArc post-quantum cryptography platform.
//!
//! # Overview
//!
//! The prelude crate serves as the foundation for error handling, domain constants,
//! and testing infrastructure across all LatticeArc components.
//!
//! # Key Components
//!
//! - **Error Handling**: Comprehensive error types with recovery mechanisms
//! - **Domain Constants**: HKDF domain separation strings for cryptographic operations
//! - **Testing Infrastructure**: CAVP compliance, property-based testing, and side-channel analysis
//!
//! # Example
//!
//! ```rust
//! use arc_prelude::prelude::{LatticeArcError, Result};
//!
//! fn example_operation() -> Result<()> {
//!     // Your cryptographic operation here
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Prelude module containing all commonly used types and utilities.
pub mod prelude;

pub use prelude::*;
