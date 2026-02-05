#![deny(unsafe_code)]
#![deny(missing_docs)]

//! TLS security properties for verification.
//!
//! Defines the security properties that TLS must guarantee:
//! - Confidentiality
//! - Authentication
//! - Forward secrecy
//!
//! **Status**: Stub implementation. Full property specifications to be implemented.

/// Security properties that TLS guarantees.
pub struct SecurityProperties;

impl SecurityProperties {
    /// Creates a new security properties checker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecurityProperties {
    fn default() -> Self {
        Self::new()
    }
}
