//! Cryptographic Policy Engine
//!
//! Provides intelligent policy-based selection of encryption and signature schemes
//! based on data characteristics, security requirements, and performance preferences.
//!
//! All types, constants, and the policy engine are defined in [`crate::types::selector`]
//! and re-exported here.

// Re-export all selector types and constants from arc-types (zero FFI deps)
pub use crate::types::selector::*;
