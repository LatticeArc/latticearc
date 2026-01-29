#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Constants for zero-trust authentication

/// Length of challenge in bytes
pub const CHALLENGE_LENGTH: usize = 32;

/// Length of proof in bytes
pub const PROOF_LENGTH: usize = 64;

/// Length of session ID in bytes
pub const SESSION_ID_LENGTH: usize = 16;

/// Length of token ID in bytes
pub const TOKEN_ID_LENGTH: usize = 16;
