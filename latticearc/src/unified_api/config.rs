//! Configuration types for LatticeArc cryptographic operations.
//!
//! Provides hierarchical configuration for encryption, signatures, zero-trust
//! authentication, and hardware acceleration.
//!
//! All types are defined in [`crate::types::config`] and re-exported here.
//! Validation methods return [`crate::types::TypeError`]; use
//! `From<TypeError> for CoreError` (in [`error`](crate::unified_api::error)) for seamless `?` conversion.

// Re-export all config types from arc-types (zero FFI deps)
pub use crate::types::config::*;
