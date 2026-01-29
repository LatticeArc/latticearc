#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Key Derivation Functions
//!
//! Provides KDFs for deriving keys from secrets following NIST standards.
//!
//! ## Supported Algorithms
//!
//! - **HKDF-SHA256**: HMAC-based Extract-and-Expand Key Derivation (NIST SP 800-56C)
//! - **PBKDF2**: Password-Based Key Derivation Function 2 (NIST SP 800-132)
//! - **SP 800-108 Counter KDF**: Counter-based Key Derivation (NIST SP 800-108)

pub mod hkdf;
pub mod pbkdf2;
pub mod sp800_108_counter_kdf;

pub use hkdf::*;
pub use pbkdf2::*;
pub use sp800_108_counter_kdf::*;
