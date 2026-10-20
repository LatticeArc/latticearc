#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Key Derivation Functions
//!
//! Provides KDFs for deriving keys from secrets and passwords following NIST
//! standards and RFC 9106.
//!
//! ## Supported Algorithms
//!
//! - **Argon2id**: Memory-hard password-based key derivation (RFC 9106).
//!   Not a NIST-approved KDF; FIPS 140-3 deployments should use PBKDF2.
//! - **HKDF-SHA256**: HMAC-based Extract-and-Expand Key Derivation (NIST SP 800-56C)
//! - **PBKDF2**: Password-Based Key Derivation Function 2 (NIST SP 800-132)
//! - **SP 800-108 Counter KDF**: Counter-based Key Derivation (NIST SP 800-108)

pub mod argon2id;
pub mod hkdf;
pub mod pbkdf2;
pub mod sp800_108_counter_kdf;

pub use argon2id::*;
pub use hkdf::*;
pub use pbkdf2::*;
pub use sp800_108_counter_kdf::*;

/// Fill a byte slice with cryptographically secure random bytes.
pub(super) fn get_random_bytes(bytes: &mut [u8]) {
    use rand::Rng;
    crate::primitives::rand::secure_rng().fill_bytes(bytes);
}
