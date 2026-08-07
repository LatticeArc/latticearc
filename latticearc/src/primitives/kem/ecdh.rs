#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! ECDH (Elliptic Curve Diffie-Hellman) Key Exchange
//!
//! This module provides X25519 (RFC 7748, 128-bit security) key agreement via
//! aws-lc-rs for FIPS 140-3 compliance and optimized performance (AVX2, AES-NI).
//! X25519 is the classical leg of the crate's hybrid KEM; no other ECDH curves
//! are exposed.
//!
//! # Performance
//!
//! aws-lc-rs provides ~4x speedup over pure-Rust implementations:
//! - Key generation: ~6µs (vs ~24µs for pure-Rust x25519)
//! - Key agreement: ~6µs (vs ~20µs for pure-Rust x25519)
//!
//! # Example
//!
//! ```no_run
//! use latticearc::primitives::kem::ecdh::X25519KeyPair;
//!
//! let alice = X25519KeyPair::generate()?;
//! let bob = X25519KeyPair::generate()?;
//!
//! let alice_pk = alice.public_key_bytes().to_vec();
//! let bob_pk = bob.public_key_bytes().to_vec();
//!
//! let alice_secret = alice.agree(&bob_pk)?;
//! let bob_secret = bob.agree(&alice_pk)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), latticearc::primitives::kem::ecdh::EcdhError>(())
//! ```

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// X25519 key size in bytes
pub const X25519_KEY_SIZE: usize = 32;

/// Error types for ECDH operations
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EcdhError {
    /// Key generation failed
    #[error("ECDH key generation failed")]
    KeyGenerationFailed,

    /// Shared secret derivation failed
    #[error("ECDH shared secret derivation failed")]
    SharedSecretDerivationFailed,

    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Key agreement failed
    #[error("ECDH key agreement failed")]
    AgreementFailed,

    /// Invalid public key (point not on curve)
    #[error("Invalid public key: point validation failed for curve {curve}")]
    InvalidPublicKey {
        /// The curve name
        curve: &'static str,
    },

    /// Invalid point format
    #[error("Invalid point format: expected {expected}, got {actual}")]
    InvalidPointFormat {
        /// Expected format description
        expected: &'static str,
        /// Actual format description
        actual: &'static str,
    },

    /// Invalid key data (rejected during import)
    #[error("Invalid key data")]
    InvalidKeyData,

    /// Invalid key material (e.g., low-order point)
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// Curve mismatch
    #[error("Curve mismatch: expected {expected}, got {actual}")]
    CurveMismatch {
        /// Expected curve name
        expected: &'static str,
        /// Actual curve name
        actual: &'static str,
    },
}

/// X25519 public key wrapper
///
/// Contains the 32-byte public key for X25519 ECDH operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey {
    bytes: [u8; X25519_KEY_SIZE],
}

/// L5 fix: constant-time comparison for `X25519PublicKey`.
///
/// The derived `PartialEq` above is varying-time and is preserved because the
/// 32-byte X25519 public key is not secret material — callers using it as a
/// `HashMap` key or in `assert_eq!` test fixtures rely on `==`. Adding a
/// `ConstantTimeEq` impl is defense-in-depth: callers that DO need timing-
/// independent comparison (e.g. CT-discipline trust-anchor pins) have it
/// without an obvious foot-gun if a future refactor secretizes the wrapped
/// bytes.
impl subtle::ConstantTimeEq for X25519PublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

/// Low-order points on Curve25519 that must be rejected per RFC 7748 §6.1.
///
/// These are the small-order subgroup elements (orders 1, 2, 4, 8) on the
/// Montgomery curve and its twist. Using any of them as a peer public key
/// forces the shared secret to be predictable (typically all-zeros), so a
/// malicious peer can learn the private scalar modulo the small subgroup.
///
/// The exact byte values mirror the `has_small_order()` blacklist in
/// libsodium's `crypto_scalarmult/curve25519/ref10/x25519_ref10.c`, which is
/// the canonical reference implementation and is itself derived from RFC 7748
/// §6.1. libsodium ships seven entries; we use the same seven, unchanged.
///
/// # Defense-in-depth rationale
///
/// aws-lc-rs (the backing implementation) may or may not reject these inputs
/// internally before invoking the X25519 scalar-mult ladder. Rather than rely
/// on that assumption, every call that accepts peer-supplied X25519 public
/// key bytes routes through `X25519PublicKey::from_bytes`, which checks this
/// list in constant time. This closes the hybrid KEM bypass where raw peer
/// bytes were previously passed directly to `agreement::agree_ephemeral` /
/// `agreement::agree` without going through the wrapper.
///
/// # Prior list note
///
/// Earlier revisions of this module carried twelve entries — the seven
/// canonical points plus five "high-bit-set" variants. Audit review found
/// that two of those variants did not match any canonical reference, and the
/// RFC 7748 §5 clamping step already masks bit 255 before the ladder runs,
/// making the extras either redundant or potentially incorrect. The list was
/// trimmed to the seven canonical points to eliminate ambiguity.
const X25519_LOW_ORDER_POINTS: [[u8; X25519_KEY_SIZE]; 7] = [
    // 0 (order 4 — identity representation).
    [0x00; 32],
    // 1 (order 1 — neutral element image).
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // Order 8 — Curve25519 small-order point
    // 325606250916557431795983626356110631294008115727848805560023387167927233504.
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // Order 8 — Curve25519 small-order point
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823.
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2).
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (order 4 — zero after reduction).
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (order 1 — one after reduction).
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

impl X25519PublicKey {
    /// Create a new X25519 public key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not exactly 32 bytes
    /// or if the key is a known low-order point on Curve25519 (RFC 7748 §6.1).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        use subtle::ConstantTimeEq;

        if bytes.len() != X25519_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: X25519_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        // Reject the 7 canonical low-order points on Curve25519 (RFC 7748 §6.1).
        // We compare in constant time using subtle::Choice so a peer cannot
        // distinguish "all-zero" from "ordered-4 point" from timing.
        let mut is_low_order = subtle::Choice::from(0u8);
        for point in &X25519_LOW_ORDER_POINTS {
            is_low_order |= bytes.ct_eq(point);
        }
        if bool::from(is_low_order) {
            return Err(EcdhError::InvalidKeyMaterial(
                "X25519 public key is a low-order point (RFC 7748 §6.1)".to_string(),
            ));
        }
        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.bytes
    }

    /// Convert to `Vec<u8>`
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

/// X25519 secret key wrapper with automatic zeroization
///
/// Contains the 32-byte secret key for X25519 ECDH operations.
/// Automatically zeroizes memory on drop to prevent key leakage.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey {
    bytes: [u8; X25519_KEY_SIZE],
}

impl X25519SecretKey {
    /// Create a new X25519 secret key from bytes
    ///
    /// # Errors
    /// Returns an error if the provided bytes are not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdhError> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(EcdhError::InvalidKeySize {
                expected: X25519_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Expose the secret key bytes.
    ///
    /// Per Secret Type Invariant I-8, this is the only public read accessor
    /// on `X25519SecretKey` so `rg expose_secret` is an exhaustive audit grep
    /// of every secret-leak surface. Callers that need a non-array slice can
    /// call `expose_secret().as_slice()`.
    ///
    /// (Renamed from `as_bytes()` in v0.8.0 dep-upgrade pass — breaking.)
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SecretKey").field("bytes", &"[REDACTED]").finish()
    }
}

impl subtle::ConstantTimeEq for X25519SecretKey {
    /// Constant-time comparison of secret key bytes.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

/// X25519 key pair containing both public and secret keys
///
/// This struct holds an ephemeral private key from aws-lc-rs along with
/// the computed public key bytes for transmission.
///
/// # Zeroization
///
/// The inner `EphemeralPrivateKey` is managed by aws-lc-rs. Zeroization of
/// the private key material on drop is delegated to the aws-lc-rs
/// (BoringSSL) allocator, which zeros memory on free. See SECURITY.md
/// ("aws-lc-rs-Wrapped Secret Types").
///
/// # Constant-Time Comparison
///
/// `ConstantTimeEq` is not implemented because the inner aws-lc-rs type
/// does not expose raw key bytes. `PartialEq` is also not implemented,
/// and a compile-time barrier in
/// `latticearc/tests/no_partial_eq_on_secret_types.rs` prevents one from
/// being added without removing the explicit assertion. See SECURITY.md
/// ("aws-lc-rs-Wrapped Secret Types").
pub struct X25519KeyPair {
    private: EphemeralPrivateKey,
    public_bytes: [u8; X25519_KEY_SIZE],
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;

        let mut public_bytes = [0u8; X25519_KEY_SIZE];
        public_bytes.copy_from_slice(public.as_ref());

        Ok(Self { private, public_bytes })
    }

    /// Get public key bytes for transmission
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.public_bytes
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey { bytes: self.public_bytes }
    }

    /// Perform X25519 key agreement with a peer's public key
    ///
    /// Consumes the private key to ensure single-use (ephemeral) semantics.
    ///
    /// Validates the peer key against the RFC 7748 §6.1 low-order point
    /// blacklist before performing the Diffie-Hellman exchange. This is
    /// defense-in-depth on top of aws-lc-rs's own validation; it ensures
    /// every caller of `agree()` gets the low-order rejection, including
    /// hybrid KEM paths that receive peer keys as raw bytes.
    ///
    /// # Errors
    /// Returns an error if the peer key is a low-order point (per RFC 7748
    /// §6.1) or key agreement fails.
    pub fn agree(
        self,
        peer_public_bytes: &[u8],
    ) -> Result<Zeroizing<[u8; X25519_KEY_SIZE]>, EcdhError> {
        // Reject low-order peer keys before reaching aws-lc-rs.
        // `from_bytes` enforces the 7-point blacklist (RFC 7748 §6.1).
        // the validated bytes are explicitly
        // documented as the source the aws-lc-rs primitive consumes —
        // `from_bytes` does not transform the bytes (X25519 PKs are
        // their own canonical form modulo the low-order check) so
        // passing the original `peer_public_bytes` to aws-lc-rs is
        // semantically identical to passing the validated copy.
        // Documenting the invariant here so a future refactor that
        // changes `from_bytes` to canonicalize cannot silently let
        // the unvalidated bytes through.
        let _validated_peer = X25519PublicKey::from_bytes(peer_public_bytes)?;
        let peer_public = UnparsedPublicKey::new(&X25519, peer_public_bytes);

        agreement::agree_ephemeral(
            self.private,
            peer_public,
            EcdhError::AgreementFailed,
            |shared_secret| {
                // Allocate the destination as `Zeroizing<[u8; 32]>`
                // first so the stack slot we copy into is owned by a
                // type that scrubs on drop. A `let mut result =
                // [0u8; 32]; ...; Ok(Zeroizing::new(result))` shape
                // leaves the unwrapped stack slot holding the secret
                // bytes after the move into Zeroizing.
                let mut result: Zeroizing<[u8; X25519_KEY_SIZE]> =
                    Zeroizing::new([0u8; X25519_KEY_SIZE]);
                result.copy_from_slice(shared_secret);
                // L-B: defense-in-depth all-zero shared-secret check,
                // mirroring the P-256 / P-384 / P-521 closures above.
                // The from_bytes(peer_public_bytes) call earlier already
                // rejects the RFC 7748 §6.1 low-order set (including the
                // all-zero key), so this is redundant under aws-lc-rs's
                // current behaviour. The check still guards against a
                // future backend swap that lets a degenerate output
                // through and keeps the CT discipline uniform across
                // ECDH variants. is_all_zero_bytes is constant-time over
                // the fixed-length slice.
                if crate::primitives::ct::is_all_zero_bytes(result.as_slice()) {
                    return Err(EcdhError::AgreementFailed);
                }
                Ok(result)
            },
        )
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// X25519 static key pair for reusable Diffie-Hellman key agreement.
///
/// Unlike [`X25519KeyPair`] which uses ephemeral keys (consumed on use),
/// this type wraps [`PrivateKey`] which supports multiple `agree()` calls
/// without consuming the key. This is essential for hybrid KEM where the
/// recipient's X25519 key must persist for decapsulation.
///
/// # Zeroization
///
/// Zeroization of the inner `PrivateKey` is delegated to aws-lc-rs
/// (BoringSSL), which zeros key material on free. See SECURITY.md
/// ("aws-lc-rs-Wrapped Secret Types").
///
/// # Constant-Time Comparison
///
/// `ConstantTimeEq` is not implemented because this type is not compared in
/// any production code path. If byte-level comparison is required, extract
/// the seed via aws-lc-rs `AsBigEndian<Curve25519SeedBin>` and compare those
/// bytes in constant time — materializing secret bytes on every compare is
/// avoided by default.
///
/// # Limitations
///
/// aws-lc-rs 1.16+ supports X25519 raw-bytes import via `from_private_key`
/// and export via `AsBigEndian<Curve25519SeedBin>`. DER encoding of X25519
/// private keys is still unsupported upstream. This wrapper currently exposes
/// only the generate/agree path; add serialization helpers if persistence
/// is needed.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::kem::ecdh::X25519StaticKeyPair;
///
/// let alice = X25519StaticKeyPair::generate()?;
/// let bob = X25519StaticKeyPair::generate()?;
///
/// // Commutativity: alice.agree(bob_pk) == bob.agree(alice_pk)
/// let ss1 = alice.agree(bob.public_key_bytes())?;
/// let ss2 = bob.agree(alice.public_key_bytes())?;
/// assert_eq!(ss1, ss2);
///
/// // Reusable: alice can agree with multiple peers
/// let carol = X25519StaticKeyPair::generate()?;
/// let ss3 = alice.agree(carol.public_key_bytes())?;
/// # Ok(())
/// # }
/// ```
pub struct X25519StaticKeyPair {
    private: PrivateKey,
    public_bytes: [u8; X25519_KEY_SIZE],
}

impl X25519StaticKeyPair {
    /// Generate a new X25519 static key pair.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, EcdhError> {
        let private = PrivateKey::generate(&X25519).map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;

        let mut public_bytes = [0u8; X25519_KEY_SIZE];
        public_bytes.copy_from_slice(public.as_ref());

        Ok(Self { private, public_bytes })
    }

    /// Get public key bytes for transmission.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.public_bytes
    }

    /// Get the public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey { bytes: self.public_bytes }
    }

    /// Export the private key seed bytes (32 bytes).
    ///
    /// These bytes can be stored and later used with [`from_seed_bytes`](Self::from_seed_bytes)
    /// to reconstruct the key pair.
    ///
    /// # Errors
    /// Returns an error if seed extraction fails.
    pub fn seed_bytes(&self) -> Result<Zeroizing<[u8; X25519_KEY_SIZE]>, EcdhError> {
        let seed: Curve25519SeedBin<'_> =
            self.private.as_be_bytes().map_err(|_e| EcdhError::KeyGenerationFailed)?;
        let mut bytes = [0u8; X25519_KEY_SIZE];
        bytes.copy_from_slice(seed.as_ref());
        Ok(Zeroizing::new(bytes))
    }

    /// Reconstruct a key pair from previously exported seed bytes.
    ///
    /// # Errors
    /// Returns an error if the seed bytes are invalid.
    pub fn from_seed_bytes(seed: &[u8; X25519_KEY_SIZE]) -> Result<Self, EcdhError> {
        let private =
            PrivateKey::from_private_key(&X25519, seed).map_err(|_e| EcdhError::InvalidKeyData)?;
        let public = private.compute_public_key().map_err(|_e| EcdhError::KeyGenerationFailed)?;

        let mut public_bytes = [0u8; X25519_KEY_SIZE];
        public_bytes.copy_from_slice(public.as_ref());

        Ok(Self { private, public_bytes })
    }

    /// Perform X25519 key agreement with a peer's public key.
    ///
    /// Unlike [`X25519KeyPair::agree`], this does **not** consume the key,
    /// allowing multiple agreements with different peers.
    ///
    /// Validates the peer key against the RFC 7748 §6.1 low-order point
    /// blacklist before performing the Diffie-Hellman exchange. This closes
    /// the hybrid KEM bypass where `HybridKemSecretKey::ecdh_agree` passes
    /// raw peer bytes to the low-level `agree()` without validation.
    ///
    /// # Errors
    /// Returns an error if the peer key is a low-order point (per RFC 7748
    /// §6.1) or key agreement fails.
    pub fn agree(
        &self,
        peer_public_bytes: &[u8],
    ) -> Result<Zeroizing<[u8; X25519_KEY_SIZE]>, EcdhError> {
        // Reject low-order peer keys before reaching aws-lc-rs.
        let _validated_peer = X25519PublicKey::from_bytes(peer_public_bytes)?;
        let peer_public = UnparsedPublicKey::new(&X25519, peer_public_bytes);

        agreement::agree(&self.private, peer_public, EcdhError::AgreementFailed, |shared_secret| {
            // See X25519KeyPair::agree above for the Zeroizing-first
            // rationale.
            let mut result: Zeroizing<[u8; X25519_KEY_SIZE]> =
                Zeroizing::new([0u8; X25519_KEY_SIZE]);
            result.copy_from_slice(shared_secret);
            // L-B: defense-in-depth all-zero shared-secret check. See
            // X25519KeyPair::agree above for the rationale.
            if crate::primitives::ct::is_all_zero_bytes(result.as_slice()) {
                return Err(EcdhError::AgreementFailed);
            }
            Ok(result)
        })
    }
}

impl std::fmt::Debug for X25519StaticKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519StaticKeyPair")
            .field("public_bytes", &self.public_bytes)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// Generate a new X25519 keypair
///
/// Returns the public key and secret key bytes. The secret key is stored
/// in a zeroizing container for security.
///
/// Validate a public key has correct size.
///
/// # Errors
/// Returns an error if the public key size does not match the expected X25519 key size.
pub fn validate_public_key(public_key: &X25519PublicKey) -> Result<(), EcdhError> {
    if public_key.as_bytes().len() != X25519_KEY_SIZE {
        return Err(EcdhError::InvalidKeySize {
            expected: X25519_KEY_SIZE,
            actual: public_key.as_bytes().len(),
        });
    }
    Ok(())
}

/// Validate a secret key has correct size.
///
/// # Errors
/// Returns an error if the secret key size does not match the expected X25519 key size.
pub fn validate_secret_key(secret_key: &X25519SecretKey) -> Result<(), EcdhError> {
    if secret_key.expose_secret().len() != X25519_KEY_SIZE {
        return Err(EcdhError::InvalidKeySize {
            expected: X25519_KEY_SIZE,
            actual: secret_key.expose_secret().len(),
        });
    }
    Ok(())
}

/// Perform X25519 key agreement
///
/// This creates an ephemeral key pair and performs Diffie-Hellman with the peer's
/// public key. For static-ephemeral or static-static DH, use `X25519KeyPair`.
///
/// # Errors
/// Returns an error if key agreement fails.
pub fn agree_ephemeral(
    peer_public_bytes: &[u8],
) -> Result<(Zeroizing<[u8; X25519_KEY_SIZE]>, [u8; X25519_KEY_SIZE]), EcdhError> {
    let keypair = X25519KeyPair::generate()?;
    let our_public = *keypair.public_key_bytes();
    let shared_secret = keypair.agree(peer_public_bytes)?;
    Ok((shared_secret, our_public))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test/bench code: unwrap is acceptable when inputs are statically known"
)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_keypair_generation_succeeds() {
        let keypair = X25519KeyPair::generate();
        assert!(keypair.is_ok());
        let keypair = keypair.unwrap();
        assert_eq!(keypair.public_key_bytes().len(), X25519_KEY_SIZE);
    }

    /// Regression: every point in `X25519_LOW_ORDER_POINTS` must be rejected
    /// both by `X25519PublicKey::from_bytes` and by the `agree()` wrappers.
    /// The seven canonical points come from libsodium's `has_small_order()`
    /// (which itself derives from RFC 7748 §6.1). If the list gets truncated
    /// or an entry stops matching, this test fails loudly instead of silently
    /// opening the bypass.
    #[test]
    fn test_all_low_order_points_rejected_fails() {
        assert_eq!(
            X25519_LOW_ORDER_POINTS.len(),
            7,
            "RFC 7748 §6.1 canonical list (libsodium) has exactly 7 points",
        );
        for (idx, point) in X25519_LOW_ORDER_POINTS.iter().enumerate() {
            let from_bytes_err = X25519PublicKey::from_bytes(point);
            assert!(
                matches!(from_bytes_err, Err(EcdhError::InvalidKeyMaterial(_))),
                "from_bytes must reject low-order point #{idx}",
            );

            let kp = X25519KeyPair::generate().unwrap();
            let agree_err = kp.agree(point);
            assert!(
                matches!(agree_err, Err(EcdhError::InvalidKeyMaterial(_))),
                "agree() must reject low-order point #{idx}",
            );
        }
    }

    #[test]
    fn test_ecdh_key_exchange_roundtrip() {
        // Generate two keypairs
        let keypair1 = X25519KeyPair::generate().unwrap();
        let keypair2 = X25519KeyPair::generate().unwrap();

        let pk1 = *keypair1.public_key_bytes();
        let pk2 = *keypair2.public_key_bytes();

        // Perform key agreement
        let ss1 = keypair1.agree(&pk2).unwrap();
        let ss2 = keypair2.agree(&pk1).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_public_key_from_bytes_succeeds() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn test_public_key_invalid_size_fails() {
        let bytes = [0x42u8; 16]; // Wrong size
        let result = X25519PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_from_bytes_succeeds() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let sk = X25519SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.expose_secret(), &bytes);
    }

    #[test]
    fn test_validate_public_key_succeeds() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert!(validate_public_key(&pk).is_ok());
    }

    #[test]
    fn test_validate_secret_key_succeeds() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let sk = X25519SecretKey::from_bytes(&bytes).unwrap();
        assert!(validate_secret_key(&sk).is_ok());
    }

    #[test]
    fn test_agree_ephemeral_roundtrip() {
        let keypair = X25519KeyPair::generate().unwrap();
        let peer_public = *keypair.public_key_bytes();

        let result = agree_ephemeral(&peer_public);
        assert!(result.is_ok());
        let (shared_secret, our_public) = result.unwrap();
        assert_eq!(shared_secret.len(), X25519_KEY_SIZE);
        assert_eq!(our_public.len(), X25519_KEY_SIZE);
    }

    // ====================================================================
    // X25519StaticKeyPair tests — proves real ECDH (not SHA-256 hash)
    // ====================================================================

    #[test]
    fn test_static_keypair_generation_succeeds() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), X25519_KEY_SIZE);
        assert!(!kp.public_key_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_static_keypair_commutativity_roundtrip() {
        // This is the key DH property: alice.agree(bob_pk) == bob.agree(alice_pk)
        let alice = X25519StaticKeyPair::generate().unwrap();
        let bob = X25519StaticKeyPair::generate().unwrap();

        let ss_ab = alice.agree(bob.public_key_bytes()).unwrap();
        let ss_ba = bob.agree(alice.public_key_bytes()).unwrap();

        assert_eq!(ss_ab, ss_ba, "DH commutativity must hold");
        assert!(!ss_ab.iter().all(|&b| b == 0), "Shared secret must not be all zeros");
    }

    #[test]
    fn test_static_keypair_reusable_succeeds() {
        // Key can be used for multiple agreements without being consumed
        let alice = X25519StaticKeyPair::generate().unwrap();
        let bob = X25519StaticKeyPair::generate().unwrap();
        let carol = X25519StaticKeyPair::generate().unwrap();

        let ss1 = alice.agree(bob.public_key_bytes()).unwrap();
        let ss2 = alice.agree(carol.public_key_bytes()).unwrap();
        let ss3 = alice.agree(bob.public_key_bytes()).unwrap();

        // Same peer → same shared secret (deterministic)
        assert_eq!(ss1, ss3, "agree() with same peer must produce same result");
        // Different peer → different shared secret
        assert_ne!(ss1, ss2, "Different peers must produce different shared secrets");
    }

    #[test]
    fn test_static_keypair_public_key_succeeds() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes(), kp.public_key_bytes());
    }

    #[test]
    fn test_static_keypair_different_keys_succeeds() {
        // Two generates must produce different key pairs
        let kp1 = X25519StaticKeyPair::generate().unwrap();
        let kp2 = X25519StaticKeyPair::generate().unwrap();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    // ====================================================================
    // X25519StaticKeyPair seed serialization tests
    // ====================================================================

    #[test]
    fn test_static_keypair_seed_roundtrip_succeeds() {
        let original = X25519StaticKeyPair::generate().unwrap();
        let seed = original.seed_bytes().unwrap();
        let restored = X25519StaticKeyPair::from_seed_bytes(&seed).unwrap();

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_static_keypair_seed_roundtrip_agree_roundtrip() {
        // Restored key must produce identical shared secrets
        let alice = X25519StaticKeyPair::generate().unwrap();
        let bob = X25519StaticKeyPair::generate().unwrap();

        let ss_original = alice.agree(bob.public_key_bytes()).unwrap();

        let seed = alice.seed_bytes().unwrap();
        let alice_restored = X25519StaticKeyPair::from_seed_bytes(&seed).unwrap();
        let ss_restored = alice_restored.agree(bob.public_key_bytes()).unwrap();

        assert_eq!(ss_original, ss_restored);
    }

    #[test]
    fn test_static_keypair_seed_not_zero_succeeds() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        let seed = kp.seed_bytes().unwrap();
        assert!(!seed.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_static_keypair_from_invalid_seed_fails() {
        // All-zero seed should still produce a valid key (X25519 clamping)
        let zero_seed = [0u8; X25519_KEY_SIZE];
        let result = X25519StaticKeyPair::from_seed_bytes(&zero_seed);
        assert!(result.is_ok());
    }

    // ====================================================================
    // X25519 additional coverage
    // ====================================================================

    #[test]
    fn test_x25519_public_key_to_vec_succeeds() {
        let bytes = [0x42u8; X25519_KEY_SIZE];
        let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_vec(), bytes.to_vec());
    }

    #[test]
    fn test_x25519_secret_key_invalid_size_fails() {
        let result = X25519SecretKey::from_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(EcdhError::InvalidKeySize { expected: 32, actual: 16 })));
    }

    #[test]
    fn test_x25519_secret_key_debug_redacted_passes_validation() {
        let sk = X25519SecretKey::from_bytes(&[0xAA; X25519_KEY_SIZE]).unwrap();
        let debug = format!("{:?}", sk);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0xaa"));
    }

    #[test]
    fn test_x25519_keypair_debug_passes_validation() {
        let kp = X25519KeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("X25519KeyPair"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_x25519_keypair_public_key_succeeds() {
        let kp = X25519KeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_x25519_static_keypair_debug_passes_validation() {
        let kp = X25519StaticKeyPair::generate().unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("X25519StaticKeyPair"));
        assert!(debug.contains("REDACTED"));
    }
}
