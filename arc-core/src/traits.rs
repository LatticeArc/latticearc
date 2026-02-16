//! Core traits for cryptographic operations.
//!
//! Defines the interfaces for encryption, decryption, signing, verification,
//! key derivation, and hardware-aware operations.
//!
//! All traits and supporting types are defined in [`arc_types::traits`]
//! and re-exported here.

// Re-export all traits from arc-types (zero FFI deps)
pub use arc_types::traits::*;
