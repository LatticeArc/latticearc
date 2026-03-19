//! CLI command implementations.
//!
//! Each module implements one subcommand. Every module follows the same pattern:
//!
//! 1. An `Args` struct (clap-derived) that defines the command's CLI flags.
//! 2. A `run(args) -> Result<()>` function that executes the command.
//! 3. Private helpers for algorithm-specific logic.
//!
//! All cryptographic operations are delegated to the `latticearc` library.
//! Command modules handle only I/O, serialization, and user-facing output.

/// Shared types for use-case and security-level driven operations.
pub(crate) mod common;
/// Symmetric and hybrid decryption (AES-256-GCM).
pub(crate) mod decrypt;
/// Symmetric and hybrid encryption (AES-256-GCM, ML-KEM+X25519).
pub(crate) mod encrypt;
/// Cryptographic hashing (SHA3-256, SHA-256, SHA-512, BLAKE2b-256).
pub(crate) mod hash;
/// Version, FIPS status, and supported algorithm display.
pub(crate) mod info;
/// Key derivation functions (HKDF-SHA256, PBKDF2-HMAC-SHA256).
pub(crate) mod kdf;
/// Key generation for 12 algorithm variants (PQC, classical, hybrid).
pub(crate) mod keygen;
/// Digital signature creation (ML-DSA, SLH-DSA, FN-DSA, Ed25519, hybrid).
pub(crate) mod sign;
/// Signature verification with automatic algorithm detection.
pub(crate) mod verify;
