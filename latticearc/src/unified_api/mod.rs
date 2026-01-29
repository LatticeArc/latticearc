#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Unified API module for LatticeArc cryptographic operations.
//!
//! This module provides a unified interface to all LatticeArc cryptographic operations,
//! including encryption, decryption, signing, verification, key derivation, and hardware-accelerated
//! operations. It also includes smart defaults for automatic scheme selection and zero-trust
//! authentication capabilities.

pub mod smart_defaults;
pub mod config;
pub mod convenience;
pub mod error;
pub mod hardware;
pub mod phi_masking;
pub mod selector;
pub mod traits;
pub mod types;
pub mod zero_trust;

pub use smart_defaults::*;
pub use config::*;
pub use convenience::{encrypt, decrypt, sign, verify};
pub use error::{CryptoError, HardwareError, VerificationError};
pub use hardware::{
    CpuAccelerator, CpuFeatures, HardwareAccelerator, HardwareCapabilities, HardwareRouter,
};
pub use phi_masking::*;
pub use selector::*;
pub use traits::*;
pub use types::*;
pub use zero_trust::*;
