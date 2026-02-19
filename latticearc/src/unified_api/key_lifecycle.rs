//! SP 800-57 Key Lifecycle Management
//!
//! This module implements formal key lifecycle management per NIST SP 800-57
//! requirements, including state transitions, custodianship, and audit trails.
//!
//! All types are defined in [`crate::types::key_lifecycle`] and re-exported here.
//! The `transition()` method returns [`crate::types::TypeError`]; use
//! `From<TypeError> for CoreError` (in [`error`](crate::unified_api::error)) for seamless `?` conversion.
//!
//! # Key States (SP 800-57 Section 3)
//!
//! - **Generation**: Key material is being generated
//! - **Active**: Key is ready for use
//! - **Rotating**: Key rotation in progress (overlap period)
//! - **Retired**: Key scheduled for retirement
//! - **Destroyed**: Key material zeroized
//!
//! # Example
//!
//! ```
//! use latticearc::unified_api::key_lifecycle::{KeyLifecycleRecord, KeyLifecycleState};
//!
//! let mut record = KeyLifecycleRecord::new(
//!     "key-123".to_string(),
//!     "ML-KEM-768".to_string(),
//!     3,   // security level
//!     365, // rotation interval (days)
//!     30,  // overlap period (days)
//! );
//!
//! // Activate the key
//! record.transition(
//!     KeyLifecycleState::Active,
//!     "alice".to_string(),
//!     "Key generation complete".to_string(),
//!     Some("approval-123".to_string()),
//! ).expect("Valid transition");
//!
//! assert!(record.is_valid_for_use());
//! ```

// Re-export all key lifecycle types from arc-types (zero FFI deps, Kani-verifiable)
pub use crate::types::key_lifecycle::*;
