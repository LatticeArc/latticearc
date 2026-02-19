#![deny(unsafe_code)]
#![deny(clippy::panic)]

//! NIST Known Answer Tests (KAT) for LatticeArc
//!
//! This module provides comprehensive NIST compliance testing including:
//! - ML-KEM (FIPS 203) test vectors
//! - ML-DSA (FIPS 204) test vectors
//! - SLH-DSA (FIPS 205) test vectors
//! - AES-GCM (NIST SP 800-38D) test vectors
//! - ChaCha20-Poly1305 (RFC 8439) test vectors
//!
//! All test vectors are derived from official NIST publications and CAVP test files.

mod aes_gcm_vectors;
mod chacha_vectors;
mod common;
mod ml_dsa_vectors;
mod ml_kem_vectors;
mod slh_dsa_vectors;
