#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(hidden_glob_reexports)]
// JUSTIFICATION: FIPS 140-3 validation framework module.
// - Statistical calculations for compliance scoring
// - Test vector processing with known NIST data structures
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

//! # FIPS Validation Framework
//!
//! This module provides comprehensive FIPS 140-3 validation capabilities for
//! cryptographic modules and implementations in LatticeArc.
//!
//! ## Supported Standards
//!
//! - **FIPS 140-3**: Security requirements for cryptographic modules
//! - **FIPS 197**: Advanced Encryption Standard (AES)
//! - **FIPS 198-1**: HMAC
//! - **FIPS 202**: SHA-3 Standard
//! - **FIPS 203/204/205**: Post-Quantum Cryptography Standards
//! - **NIST SP 800-107**: Key Derivation Functions
//! - **NIST SP 800-38B**: CMAC
//!
//! ## Features
//!
//! - **Module Validation**: Automated FIPS compliance checking
//! - **Algorithm Validation**: Individual cryptographic algorithm testing using NIST test vectors
//! - **Key Management**: FIPS-compliant key generation and handling
//! - **Self-Tests**: Automated power-up and conditional self-tests
//! - **Certificate Generation**: FIPS validation certificate management
//!
//! ## NIST Test Vectors
//!
//! All validation tests use official NIST test vectors from:
//! - FIPS 197 AES Test Vectors (csrc.nist.gov)
//! - FIPS 202 SHA-3 Test Vectors (csrc.nist.gov)
//! - FIPS 203 ML-KEM Test Vectors (csrc.nist.gov)
//! - SP 800-107 KDF Test Vectors (csrc.nist.gov)
//!
//! ## Module Organization
//!
//! - `types` - Core types (ValidationScope, FIPSLevel, ValidationResult, etc.)
//! - `validator` - FIPSValidator struct and validation logic
//! - `global` - Global FIPS state and initialization functions
//! - `algorithm_tests` - AES, SHA-3, ML-KEM algorithm tests
//! - `interface_tests` - API and key management interface tests
//! - `policy_tests` - Self-tests and error handling tests
//!
//! ## Usage
//!
//! ```rust,ignore
//! use arc_validation::fips_validation::{FIPSValidator, ValidationScope};
//!
//! // Create FIPS validator
//! let validator = FIPSValidator::new(ValidationScope::FullModule);
//!
//! // Perform FIPS validation
//! let result = validator.validate_module()?;
//!
//! if result.is_valid() {
//!     tracing::info!("FIPS validation passed - Level {:?}", result.level);
//!
//!     // Generate validation certificate
//!     let certificate = validator.generate_certificate(&result)?;
//!     tracing::info!("Validation certificate: {}", certificate.id);
//! } else {
//!     tracing::error!("FIPS validation failed");
//!
//!     // Get remediation guidance
//!     let remediation = validator.get_remediation_guidance(&result);
//!     for item in remediation {
//!         tracing::info!("Remediation: {}", item);
//!     }
//! }
//! ```

mod algorithm_tests;
mod global;
mod interface_tests;
mod policy_tests;
mod types;
mod validator;

// Re-export public types
pub use types::{
    FIPSLevel, IssueSeverity, TestResult, ValidationCertificate, ValidationIssue, ValidationResult,
    ValidationScope,
};

// Re-export validator
pub use validator::FIPSValidator;

// Re-export global functions
pub use global::{
    continuous_rng_test, get_fips_validation_result, init, is_fips_initialized,
    run_conditional_self_test,
};

// Re-export from other FIPS modules
pub use crate::fips_validation_impl::*;
pub use crate::kat_tests::*;
pub use crate::nist_sp800_22::*;
pub use crate::validation_summary::*;
