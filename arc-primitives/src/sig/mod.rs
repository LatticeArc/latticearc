#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Digital Signatures
//!
//! This module provides a unified interface for both post-quantum and classical
//! digital signature schemes. It supports the following algorithms:
//!
//! ## Post-Quantum Algorithms
//!
//! ### ML-DSA (FIPS 204)
//! Module-Lattice-Based Digital Signature Algorithm providing EUF-CMA security.
//!
//! - **ML-DSA-44**: NIST Security Category 2 (~128-bit classical security)
//!   - Public key: 1312 bytes
//!   - Secret key: 2560 bytes
//!   - Signature: ~2.4 KB
//!
//! - **ML-DSA-65**: NIST Security Category 3 (~192-bit classical security)
//!   - Public key: 1952 bytes
//!   - Secret key: 4032 bytes
//!   - Signature: ~3.3 KB
//!
//! - **ML-DSA-87**: NIST Security Category 5 (~256-bit classical security)
//!   - Public key: 2592 bytes
//!   - Secret key: 4896 bytes
//!   - Signature: ~4.6 KB
//!
//! ### SLH-DSA (FIPS 205)
//! Stateless Hash-Based Digital Signature Algorithm providing EUF-CMA security
//! with conservative security guarantees.
//!
//! - **SLH-DSA-SHAKE-128s**: NIST Security Category 1
//!   - Very long keys, but quantum-resistant
//!   - Stateless: No secret state that needs updating
//!   - Signatures can be made as many times as needed
//!
//! - **SLH-DSA-SHAKE-192s**: NIST Security Category 3
//!   - Balanced security and performance
//!
//! - **SLH-DSA-SHAKE-256s**: NIST Security Category 5
//!   - Highest security level
//!
//! ### FN-DSA (FIPS 206)
//! Few-Time Digital Signature Algorithm based on NTRU lattice.
//! Provides compact signatures with lattice-based security.
//!
//! - **FN-DSA-512**: ~128-bit security (Level I)
//!   - Public key: 897 bytes
//!   - Secret key: 1281 bytes
//!   - Signature: 666 bytes
//!
//! - **FN-DSA-1024**: ~256-bit security (Level V)
//!   - Public key: 1793 bytes
//!   - Secret key: 2305 bytes
//!   - Signature: 1280 bytes
//!
//! ## Classical Algorithms
//!
//! - **ECDSA**: Elliptic Curve Digital Signature Algorithm
//!   - P-256, P-384, P-521 curves
//!
//! - **Ed25519**: EdDSA signature scheme using Curve25519
//!   - Fast, secure, widely adopted
//!
//! ## Security Properties
//!
//! All signature implementations in this module provide:
//!
//! - **EUF-CMA**: Existential Unforgeability under Chosen Message Attacks
//!   - An adversary cannot forge a valid signature even when given
//!     signatures on arbitrary messages of their choice
//!
//! - **Constant-time**: All secret-handling operations execute in constant time
//!   - Protects against timing side-channel attacks
//!
//! - **Zeroization**: Secret keys are securely wiped when dropped
//!   - Prevents secret material from remaining in memory
//!
//! - **Domain Separation**: Optional context string parameter
//!   - Prevents signature reuse across different applications
//!
//! ## Algorithm Comparison
//!
//! | Algorithm | Key Size | Signature Size | Security | Best For |
//! |-----------|-----------|----------------|----------|----------|
//! | ML-DSA-44 | ~2.4 KB | ~2.4 KB | 128-bit | Balanced security/performance |
//! | ML-DSA-65 | ~3.6 KB | ~3.3 KB | 192-bit | High-security applications |
//! | ML-DSA-87 | ~4.6 KB | ~4.6 KB | 256-bit | Maximum security |
//! | SLH-DSA-SHAKE | Large | ~41 KB | Conservative | Long-term security, stateless |
//! | FN-DSA-512 | ~1.3 KB | 666 bytes | 128-bit | Compact signatures, fast verify |
//! | FN-DSA-1024 | ~2.3 KB | 1280 bytes | 256-bit | High-security with compact sigs |
//!
//! ## Example Usage
//!
//! ### ML-DSA Signing and Verification
//!
//! ```no_run
//! use arc_primitives::sig::{MlDsaParameterSet, generate_keypair, sign, verify};
//!
//! // Generate keypair
//! let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65)?;
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = sign(&sk, message, &[])?;
//!
//! // Verify signature
//! let is_valid = verify(&pk, message, &signature, &[])?;
//! assert!(is_valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### SLH-DSA with Context
//!
//! ```no_run
//! use arc_primitives::sig::slh_dsa::{SecurityLevel, SigningKey, VerifyingKey};
//!
//! let (sk, pk) = SigningKey::generate(SecurityLevel::Shake128s)?;
//!
//! let message = b"Important document";
//! let context = b"my-application-v1"; // Domain separation
//!
//! let signature = sk.sign(message, Some(context))?;
//! let is_valid = pk.verify(message, &signature, Some(context))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## FIPS Compliance
//!
//! All post-quantum signature algorithms are fully compliant with their respective FIPS standards:
//!
//! - **ML-DSA**: [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final/)
//! - **SLH-DSA**: [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final/)
//! - **FN-DSA**: [FIPS 206](https://csrc.nist.gov/pubs/fips/206/final/)
//!
//! All implementations use audited FIPS-standard crates (fips204, fips205, fn-dsa).
//!
//! ## Mathematical Correctness
//!
//! ### ML-DSA
//! Based on Module-SIS (Short Integer Solution) lattice problem.
//! The security reduction proves that forging a signature requires solving
//! the Module-SIS problem, which is believed to be hard for quantum computers.
//!
//! ### SLH-DSA
//! Based on Merkle tree hash-based signatures. Security relies on
//! collision resistance of the underlying hash function (SHAKE).
//! Provides information-theoretic security against quantum attacks.
//!
//! ### FN-DSA
//! Based on the NTRU lattice problem (Shortest Vector Problem).
//! Provides provable security with compact signatures.
//!
//! ## Security Considerations
//!
//! - **Key Generation**: Always use cryptographically secure random number generators
//! - **Key Storage**: Store secret keys securely, never transmit them
//! - **Signature Reuse**: SLH-DSA is stateless (no signature reuse concerns)
//! - **Context Parameter**: Use non-empty context strings for domain separation
//! - **Algorithm Selection**: Choose algorithm based on your security requirements
//!   and performance constraints
//!
//! ## Module Structure
//!
//! - [`ml_dsa`]: ML-DSA (FIPS 204) lattice-based signatures
//! - [`slh_dsa`]: SLH-DSA (FIPS 205) hash-based signatures
//! - [`fndsa`]: FN-DSA (FIPS 206) compact lattice signatures

pub mod fndsa;
pub mod ml_dsa;
pub mod slh_dsa;

// Re-exports for convenience
pub use fndsa::*;
pub use ml_dsa::*;
pub use slh_dsa::*;
