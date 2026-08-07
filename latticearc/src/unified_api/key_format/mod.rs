#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
//! LatticeArc Portable Key Format (LPK v1)
//!
//! Schema-first dual-format key serialization supporting JSON (human-readable)
//! and CBOR (compact binary, RFC 8949) for all LatticeArc key types.
//!
//! # Design Principles
//!
//! - **Schema-first**: One Rust struct, two wire formats (JSON + CBOR)
//! - **CBOR primary**: Wire protocol, database storage, enterprise containers
//! - **JSON secondary**: CLI display, REST APIs, debugging, key export
//! - **Standards-aligned**: Algorithm IDs from FIPS 203-206 / RFC 7748 / RFC 8032;
//!   composite key layout follows `draft-ietf-lamps-pq-composite-kem` (concatenation);
//!   JWK-compatible structure (per `draft-ietf-jose-pqc-kem`)
//!
//! # Key Identity
//!
//! Keys are identified by **use case** or **security level** — mirroring
//! how the library's API works. The algorithm is auto-derived and stored
//! internally for version-stability.
//!
//! # JSON Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "use_case": "file-storage",
//!   "algorithm": "hybrid-ml-kem-1024-x25519",
//!   "key_type": "public",
//!   "key_data": { "raw": "Base64..." },
//!   "created": "2026-03-19T..."
//! }
//! ```
//!
//! # CBOR Format
//!
//! Same logical schema. Key material stored as CBOR byte strings (`bstr`) —
//! no base64 encoding, no string overhead. See [`crate::unified_api::key_format::PortableKey::to_cbor`].
//!
//! # Enterprise Extension Model
//!
//! The `metadata` field is an open `BTreeMap<String, serde_json::Value>`.
//! Enterprise crates add dimensions, key expiry,
//! hardware binding, etc. via extension traits — the base library preserves
//! unknown metadata keys during roundtrips without modification:
//!
//! ```text
//! // Enterprise crate — typed accessors over the metadata map (pseudocode)
//! impl EnterpriseKeyExt for PortableKey {
//!     fn dimensions(&self) -> Option<Vec<String>> { ... }
//!     fn key_expiry(&self) -> Option<DateTime<Utc>> { ... }
//!     fn hsm_binding(&self) -> Option<HsmSlot> { ... }
//! }
//! ```

/// Metadata key for the ML-KEM public key stored in hybrid secret key files.
/// Used in `from_hybrid_kem_keypair` (write) and `to_hybrid_secret_key` (read).
const ML_KEM_PK_METADATA_KEY: &str = "ml_kem_pk";

// --- Passphrase-encryption envelope constants (LPK v1 encrypted variant) ---

/// Current version of the encrypted-key envelope schema.
///
/// Each bump marks an AEAD AAD-layout change. An envelope written by an
/// older version has the same wire shape but a different AAD, so a newer
/// verifier's AAD will not match and AEAD authentication fails. Without a
/// version field that failure is indistinguishable from a wrong
/// passphrase. Bumping the field on every AAD change lets the loader emit
/// a distinct "old envelope; re-protect" error so users decrypt and
/// re-encrypt rather than chase a passphrase that was already correct.
///
/// History:
/// - `1` → `2`: metadata-binding fix; AAD magic `lpk-v1-enc` → `lpk-v2-enc`.
/// - `2` → `3`: AAD canonicalization fix — a null terminator was added
///   after the `aead` string field; AAD magic `lpk-v2-enc` → `lpk-v3-enc`.
///   See `encryption_aad` for the layout.
const ENCRYPTED_ENVELOPE_VERSION: u32 = 3;
/// KDF identifier for the encrypted-key envelope.
const PBKDF2_KDF_ID: &str = "PBKDF2-HMAC-SHA256";
/// AEAD identifier for the encrypted-key envelope.
const AES_GCM_AEAD_ID: &str = "AES-256-GCM";
/// PBKDF2 default iteration count (OWASP 2023 recommendation for HMAC-SHA256).
const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;
/// PBKDF2 minimum iteration count accepted when loading an encrypted key.
const PBKDF2_MIN_ITERATIONS: u32 = 100_000;
/// PBKDF2 maximum iteration count accepted when loading an encrypted key.
///
/// an attacker-supplied envelope with `kdf_iterations =
/// u32::MAX` (4.3 billion) would force tens of minutes of HMAC-SHA256 work
/// per decrypt attempt, denying service to the legitimate keyholder. This
/// upper bound is two orders of magnitude above the OWASP-2023
/// recommendation (600 k) and well above any reasonable interactive-login
/// budget, so it does not constrain legitimate callers.
const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;
/// PBKDF2 salt length in bytes (SP 800-132 recommends ≥ 16).
const PBKDF2_SALT_LEN: usize = 16;
/// PBKDF2 minimum salt length accepted when loading an encrypted key.
/// Re-exported from the canonical NIST SP 800-132 §5.1 constant on
/// [`Pbkdf2Params::MIN_SALT_LEN`](crate::primitives::kdf::pbkdf2::Pbkdf2Params::MIN_SALT_LEN)
/// so the load-side check and the construction-side check cannot drift.
const PBKDF2_MIN_SALT_LEN: usize = crate::primitives::kdf::pbkdf2::Pbkdf2Params::MIN_SALT_LEN;
/// AES-256-GCM nonce length in bytes (NIST SP 800-38D).
const AES_GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM tag length in bytes.
const AES_GCM_TAG_LEN: usize = 16;
/// AES-256 key length in bytes.
const AES_256_KEY_LEN: usize = 32;

mod algorithm;
mod conversions;
mod encryption;
mod key_data;
mod key_type;
mod portable_key_core;
mod serialization;
#[cfg(test)]
mod tests_a;
#[cfg(test)]
mod tests_b;
mod validation;

pub use algorithm::KeyAlgorithm;
pub use key_data::{KeyData, ZeroizingKeyPair};
pub use key_type::KeyType;
pub use portable_key_core::PortableKey;
