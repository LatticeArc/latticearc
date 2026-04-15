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
//! │  │           │   HKDF dual-PRF  │      AND           │            │   │
//! │  │           │    combiner      │  Composition       │            │   │
//! │  │           └──────────────────┴────────────────────┘            │   │
//! │  │                              │                                 │   │
//! │  │  ┌───────────────────────────┴───────────────────────────────┐ │   │
//! │  │  │                    compose module                         │ │   │
//! │  │  │  - HKDF dual-PRF combiner (secure if EITHER is secure)    │ │   │
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
//! - [`pq_only`](mod@crate::hybrid::pq_only) - PQ-only encryption using ML-KEM + HKDF + AES-256-GCM (no X25519)
//!
//! # Security Properties
//!
//! | Construction      | Composition     | Security Guarantee                    |
//! |-------------------|-----------------|---------------------------------------|
//! | Hybrid KEM        | HKDF dual-PRF   | Secure if ML-KEM OR X25519 is secure  |
//! | Hybrid Signature  | AND             | Secure if ML-DSA AND Ed25519 secure   |
//! | Hybrid Encryption | HKDF dual-PRF   | Secure if either KEM component secure |
//! | PQ-Only Encrypt   | ML-KEM + HKDF   | Secure if ML-KEM is secure            |

pub mod compose;
pub mod encrypt_hybrid;
pub mod kem_hybrid;
pub mod pq_only;
pub mod sig_hybrid;

// Re-exports for convenience - use explicit exports to avoid ambiguity.
// All hybrid types are reachable directly via `crate::hybrid::*`; the previous
// `hybrid::kem` / `hybrid::sig` / `hybrid::encrypt` inline re-export modules
// were removed as they duplicated this surface.
pub use encrypt_hybrid::{
    HybridCiphertext, HybridEncryptionContext, HybridEncryptionError, decrypt_hybrid,
    derive_encryption_key, encrypt_hybrid,
};
pub use kem_hybrid::{
    EncapsulatedKey, HybridKemError, HybridKemPublicKey, HybridKemSecretKey,
    HybridSharedSecretInputs, decapsulate, derive_hybrid_shared_secret, encapsulate,
    generate_keypair as kem_generate_keypair,
};
pub use pq_only::{
    PqOnlyCiphertext, PqOnlyError, PqOnlyPublicKey, PqOnlySecretKey, decrypt_pq_only,
    encrypt_pq_only, generate_pq_keypair, generate_pq_keypair_with_level,
};
pub use sig_hybrid::{
    HybridSigPublicKey, HybridSigSecretKey, HybridSignature, HybridSignatureError,
    generate_keypair as sig_generate_keypair, sign, verify,
};
