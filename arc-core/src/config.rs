//! Configuration types for LatticeArc cryptographic operations.
//!
//! Provides hierarchical configuration for encryption, signatures, zero-trust
//! authentication, and hardware acceleration.
//!
//! All types are defined in [`arc_types::config`] and re-exported here.
//! Validation methods return [`arc_types::TypeError`]; use
//! `From<TypeError> for CoreError` (in [`crate::error`]) for seamless `?` conversion.

// Re-export all config types from arc-types (zero FFI deps)
pub use arc_types::config::*;
