//! Domain Separation Constants for HKDF
//!
//! This module provides domain separation strings used in HKDF key derivation
//! to ensure cryptographic isolation between different cryptographic operations.
//!
//! Domain separation prevents key reuse across different protocols and ensures
//! that keys derived for one purpose cannot be used for another.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Domain for hybrid KEM key derivation.
///
/// Used when deriving keys from hybrid key encapsulation mechanisms
/// combining X25519 classical key exchange with ML-KEM-1024 post-quantum KEM.
pub const HYBRID_KEM: &[u8] = b"LatticeArc-v1-HybridKEM-X25519-MLKEM1024";

/// Domain for cascaded encryption outer layer.
///
/// Used for the outer encryption layer when applying cascaded encryption
/// with ChaCha20-Poly1305 for defense in depth.
pub const CASCADE_OUTER: &[u8] = b"LatticeArc-v1-Cascade-ChaCha20Poly1305";

/// Domain for cascaded encryption inner layer.
///
/// Used for the inner encryption layer when applying cascaded encryption
/// with AES-256-GCM for defense in depth.
pub const CASCADE_INNER: &[u8] = b"LatticeArc-v1-Cascade-AES256GCM";

/// Domain for signature binding.
///
/// Used when binding dual signatures combining Ed25519 classical signatures
/// with ML-DSA-87 post-quantum signatures for hybrid authentication.
pub const SIGNATURE_BIND: &[u8] = b"LatticeArc-v1-DualSignature-Ed25519-MLDSA87";
