//! Error Handling Module
//!
//! This module provides comprehensive error types for the LatticeArc library.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Core error types and result handling.
pub mod types;

pub use types::{LatticeArcError, Result};
