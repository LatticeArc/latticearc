#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Message Authentication Codes
//!
//! Provides MAC algorithms (HMAC, CMAC).

pub mod cmac;
pub mod hmac;

pub use cmac::*;
pub use hmac::*;
