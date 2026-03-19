//! Hybrid Cryptography for LatticeArc
//!
//! This module provides hybrid cryptographic schemes that combine post-quantum
//! and classical algorithms for enhanced security during the quantum transition period.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        HYBRID CRYPTOGRAPHY LAYER                        │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Hybrid Constructions                         │   │
//! │  │                                                                 │   │
//! │  │   ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐  │   │
//! │  │   │ kem_hybrid    │  │ sig_hybrid    │  │ encrypt_hybrid    │  │   │
//! │  │   │               │  │               │  │                   │  │   │
//! │  │   │ ML-KEM-768    │  │ ML-DSA-65     │  │ Hybrid KEM +      │  │   │
//! │  │   │    +          │  │    +          │  │ AES-256-GCM       │  │   │
//! │  │   │ X25519        │  │ Ed25519       │  │                   │  │   │
//! │  │   └───────┬───────┘  └───────┬───────┘  └─────────┬─────────┘  │   │
//! │  │           │                  │                    │            │   │
//! │  │           │     XOR          │      AND           │            │   │
//! │  │           │  Composition     │  Composition       │            │   │
//! │  │           └──────────────────┴────────────────────┘            │   │
//! │  │                              │                                 │   │
//! │  │  ┌───────────────────────────┴───────────────────────────────┐ │   │
//! │  │  │                    compose module                         │ │   │
//! │  │  │  - XOR composition proof (breaks EITHER = breaks HYBRID)  │ │   │
//! │  │  │  - AND composition proof (breaks BOTH = breaks HYBRID)    │ │   │
//! │  │  └───────────────────────────────────────────────────────────┘ │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                    │                                   │
//! │                                    ▼                                   │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    primitives (Core Algorithms)                 │   │
//! │  │                                                                 │   │
//! │  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │   │
//! │  │   │   ML-KEM     │  │   ML-DSA     │  │     Classical        │ │   │
//! │  │   │  FIPS 203    │  │  FIPS 204    │  │  X25519, Ed25519     │ │   │
//! │  │   │  aws-lc-rs   │  │  fips204     │  │  aws-lc-rs           │ │   │
//! │  │   └──────────────┘  └──────────────┘  └──────────────────────┘ │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! Security Guarantee: Hybrid remains secure if EITHER algorithm is secure
//! ```
//!
//! # Modules
//!
//! - [`encrypt_hybrid`](mod@crate::hybrid::encrypt_hybrid) - Hybrid encryption using ML-KEM + AES-256-GCM
//! - [`kem_hybrid`](crate::hybrid::kem_hybrid) - Hybrid key encapsulation using ML-KEM + X25519
//! - [`sig_hybrid`](crate::hybrid::sig_hybrid) - Hybrid signatures using ML-DSA + Ed25519
//! - [`compose`](crate::hybrid::compose) - Formal security proofs for hybrid composition
//!
//! # Security Properties
//!
//! | Construction      | Composition | Security Guarantee                    |
//! |-------------------|-------------|---------------------------------------|
//! | Hybrid KEM        | XOR         | Secure if ML-KEM OR X25519 is secure  |
//! | Hybrid Signature  | AND         | Secure if ML-DSA AND Ed25519 secure   |
//! | Hybrid Encryption | XOR (KEM)   | Secure if either KEM component secure |

pub mod compose;
pub mod encrypt_hybrid;
pub mod kem_hybrid;
pub mod sig_hybrid;

/// Hybrid key encapsulation mechanism types and functions.
///
/// Re-exports all public items from [`kem_hybrid`].
pub mod kem {
    pub use crate::hybrid::kem_hybrid::*;
}

/// Hybrid signature types and functions.
///
/// Re-exports all public items from [`sig_hybrid`].
pub mod sig {
    pub use crate::hybrid::sig_hybrid::*;
}

/// Hybrid encryption types and functions.
///
/// Re-exports all public items from [`encrypt_hybrid`](mod@crate::hybrid::encrypt_hybrid).
pub mod encrypt {
    pub use crate::hybrid::encrypt_hybrid::*;
}

// Re-exports for convenience - use explicit exports to avoid ambiguity
pub use encrypt_hybrid::{
    HybridCiphertext, HybridEncryptionContext, HybridEncryptionError, decrypt, decrypt_hybrid,
    derive_encryption_key, encrypt, encrypt_hybrid,
};
pub use kem_hybrid::{
    EncapsulatedKey, HybridKemError, HybridPublicKey as KemHybridPublicKey,
    HybridSecretKey as KemHybridSecretKey, decapsulate, derive_hybrid_shared_secret, encapsulate,
    generate_keypair as kem_generate_keypair,
};
pub use sig_hybrid::{
    HybridPublicKey as SigHybridPublicKey, HybridSecretKey as SigHybridSecretKey, HybridSignature,
    HybridSignatureError, generate_keypair as sig_generate_keypair, sign, verify,
};
