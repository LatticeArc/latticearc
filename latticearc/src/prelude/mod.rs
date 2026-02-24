//! LatticeArc Prelude Crate
//!
//! This module provides common types, traits, and utilities used throughout
//! the LatticeArc post-quantum cryptography platform.
//!
//! # Overview
//!
//! The prelude module serves as the foundation for error handling, domain constants,
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
//! use latticearc::prelude::prelude::{LatticeArcError, Result};
//!
//! fn example_operation() -> Result<()> {
//!     // Your cryptographic operation here
//!     Ok(())
//! }
//! ```

/// Prelude module containing all commonly used types and utilities.
#[allow(clippy::module_inception)]
pub mod prelude;

pub use prelude::*;
