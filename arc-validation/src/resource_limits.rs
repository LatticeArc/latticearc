//! Resource limits for cryptographic operations.
//!
//! This module re-exports [`arc_types::resource_limits`] for backwards compatibility.
//! The canonical implementation now lives in `arc-types` (zero-dependency crate).

pub use arc_types::resource_limits::*;
