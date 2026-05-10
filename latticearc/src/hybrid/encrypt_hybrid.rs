#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hybrid Encryption Module
//!
//! This module provides hybrid encryption combining post-quantum (ML-KEM) key
//! encapsulation with AES-256-GCM symmetric encryption for quantum-resistant
//! data encryption with classical performance characteristics.
//!
//! # Overview
//!
//! The hybrid encryption scheme uses:
//! - **ML-KEM-768** (FIPS 203) for post-quantum key encapsulation
//! - **AES-256-GCM** for authenticated symmetric encryption
//! - **HKDF-SHA256** for key derivation with domain separation
//!
//! # Security Properties
//!
//! - IND-CCA2 security from ML-KEM
//! - Authenticated encryption with associated data (AEAD)
//! - Domain separation via HPKE-style key derivation
//!
//! # Example
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::hybrid::encrypt_hybrid::{
//!     encrypt_hybrid, decrypt_hybrid, HybridEncryptionContext,
//! };
//! use latticearc::hybrid::kem_hybrid;
//! use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
//!
//! // Generate a hybrid (ML-KEM + X25519) keypair at the desired security level.
//! let (hybrid_pk, hybrid_sk) =
//!     kem_hybrid::generate_keypair_with_level(MlKemSecurityLevel::MlKem768)?;
//!
//! let plaintext = b"Secret message";
//! let context = HybridEncryptionContext::default();
//!
//! let ciphertext = encrypt_hybrid(&hybrid_pk, plaintext, Some(&context))?;
//! let decrypted = decrypt_hybrid(&hybrid_sk, &ciphertext, Some(&context))?;
//! # Ok(())
//! # }
//! ```

use crate::hybrid::kem_hybrid::{self, HybridKemPublicKey, HybridKemSecretKey};
use crate::log_crypto_operation_error;
use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, NONCE_LEN, TAG_LEN};
use crate::primitives::kdf::hkdf::hkdf;
use crate::unified_api::logging::op;
use thiserror::Error;
use zeroize::Zeroizing;

/// Error types for hybrid encryption operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid encryption and decryption operations.
// PartialEq intentionally not derived (see `HybridSignatureError`).
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub enum HybridEncryptionError {
    /// Error during key encapsulation mechanism operations.
    #[error("KEM error: {0}")]
    KemError(String),
    /// Error during symmetric encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    /// Error during symmetric decryption or authentication failure.
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    /// Error during key derivation function operations.
    #[error("Key derivation error: {0}")]
    KdfError(String),
    /// Invalid input parameters provided to the operation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Key length mismatch error.
    #[error("Key length error: expected {expected}, got {actual}")]
    KeyLengthError {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },
}

/// Hybrid ciphertext containing both KEM and symmetric encryption components.
///
/// This structure holds all the data needed to decrypt a hybrid-encrypted message:
/// - The KEM ciphertext for key decapsulation
/// - The symmetric ciphertext containing the encrypted message
/// - The nonce used for AES-GCM encryption
/// - The authentication tag for integrity verification
#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    /// ML-KEM ciphertext for key decapsulation (1088 bytes for ML-KEM-768).
    kem_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key for ECDH (exactly 32 bytes).
    /// previously documented as "Empty for legacy ML-KEM-
    /// only ciphertexts." That contract was always dead — `decrypt_hybrid`
    /// rejects any `len() != 32` (see `decrypt_hybrid` validation block).
    /// All current callers must pass a 32-byte ephemeral X25519 PK.
    ecdh_ephemeral_pk: Vec<u8>,
    /// AES-256-GCM encrypted message data.
    symmetric_ciphertext: Vec<u8>,
    /// 12-byte nonce used for AES-GCM encryption.
    nonce: Vec<u8>,
    /// 16-byte AES-GCM authentication tag.
    tag: Vec<u8>,
}

impl HybridCiphertext {
    /// Construct a new `HybridCiphertext` from its components.
    ///
    /// # Parameters
    ///
    /// - `kem_ciphertext`: ML-KEM ciphertext for key decapsulation (1088 bytes for ML-KEM-768).
    /// - `ecdh_ephemeral_pk`: X25519 ephemeral public key (exactly 32 bytes).
    /// - `symmetric_ciphertext`: AES-256-GCM encrypted message data.
    /// - `nonce`: 12-byte nonce used for AES-GCM encryption.
    /// - `tag`: 16-byte AES-GCM authentication tag.
    #[must_use]
    pub fn new(
        kem_ciphertext: Vec<u8>,
        ecdh_ephemeral_pk: Vec<u8>,
        symmetric_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        tag: Vec<u8>,
    ) -> Self {
        Self { kem_ciphertext, ecdh_ephemeral_pk, symmetric_ciphertext, nonce, tag }
    }

    /// Returns the ML-KEM ciphertext bytes.
    #[must_use]
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    /// Returns the X25519 ephemeral public key bytes (always 32 bytes).
    ///
    /// The legacy "empty for ML-KEM-only ciphertexts" contract was
    /// always dead — `decrypt_hybrid` rejected anything other than 32
    /// bytes. See the field doc on
    /// [`HybridCiphertext::ecdh_ephemeral_pk`] above for the
    /// audit trail.
    #[must_use]
    pub fn ecdh_ephemeral_pk(&self) -> &[u8] {
        &self.ecdh_ephemeral_pk
    }

    /// Returns the AES-256-GCM symmetric ciphertext bytes.
    #[must_use]
    pub fn symmetric_ciphertext(&self) -> &[u8] {
        &self.symmetric_ciphertext
    }

    /// Returns the 12-byte AES-GCM nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the 16-byte AES-GCM authentication tag.
    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Returns a mutable reference to the ML-KEM ciphertext bytes.
    pub fn kem_ciphertext_mut(&mut self) -> &mut Vec<u8> {
        &mut self.kem_ciphertext
    }

    /// Returns a mutable reference to the X25519 ephemeral public key bytes.
    pub fn ecdh_ephemeral_pk_mut(&mut self) -> &mut Vec<u8> {
        &mut self.ecdh_ephemeral_pk
    }

    /// Returns a mutable reference to the AES-256-GCM symmetric ciphertext bytes.
    pub fn symmetric_ciphertext_mut(&mut self) -> &mut Vec<u8> {
        &mut self.symmetric_ciphertext
    }

    /// Returns a mutable reference to the 12-byte AES-GCM nonce.
    pub fn nonce_mut(&mut self) -> &mut Vec<u8> {
        &mut self.nonce
    }

    /// Returns a mutable reference to the 16-byte AES-GCM authentication tag.
    pub fn tag_mut(&mut self) -> &mut Vec<u8> {
        &mut self.tag
    }
}

/// HPKE-style context information for hybrid encryption.
///
/// This structure provides domain separation and additional authenticated data
/// for the key derivation and encryption operations, following RFC 9180 (HPKE).
// manual `Debug` (below) redacts `aad`. The previous
// `#[derive(Debug)]` would dump the full AAD to any
// `tracing::debug!("{:?}", ctx)` call — and AAD here is documented as
// per-message application data (transport headers, request IDs, version
// tags), much of which is reasonably treated as confidential by callers.
// `info` is the domain-separation label, also redacted to its length to
// keep both fields opaque-by-default.
#[derive(Clone)]
pub struct HybridEncryptionContext {
    /// Application-specific info string for key derivation domain separation.
    ///
    /// Private (Pattern 7): callers must go through [`Self::default`],
    /// [`Self::with_aad`], or [`Self::with_explicit_info`] so the only way
    /// to set a non-default `info` is to make a deliberate, grep-able call.
    /// A `pub` field would let any caller silently collide with another
    /// protocol's domain-separation label.
    info: Vec<u8>,
    /// Additional authenticated data (AAD) for AEAD encryption.
    ///
    /// Intentionally `pub` (asymmetric with `info`): AAD is per-message
    /// application data — transport headers, request IDs, version tags —
    /// that callers MUST set at every call site. It carries no domain-
    /// separation role, so the grep-able-audit motivation that privatizes
    /// `info` does not apply. AAD mismatches surface as ordinary
    /// authentication failures (no oracle) and are visible to legitimate
    /// callers by design.
    ///
    /// **Length bound:** [`Self::MAX_AAD_LEN`] (64 KiB). The bound is
    /// enforced at [`encrypt_hybrid`] / [`decrypt_hybrid`] entry, before
    /// any AEAD or KEM work runs. Real-world AAD payloads (transport
    /// headers, request IDs, content-type strings) sit well below this
    /// cap; the limit exists to bound DoS surface, not to constrain
    /// legitimate callers.
    pub aad: Vec<u8>,
}

impl std::fmt::Debug for HybridEncryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // redact both fields to lengths. `aad` is
        // application-controlled (request IDs, headers) that callers
        // may consider confidential; `info` is a domain-separation
        // label whose contents would just be noise in a log.
        f.debug_struct("HybridEncryptionContext")
            .field("info_len", &self.info.len())
            .field("aad_len", &self.aad.len())
            .finish()
    }
}

impl Default for HybridEncryptionContext {
    fn default() -> Self {
        Self { info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(), aad: vec![] }
    }
}

impl HybridEncryptionContext {
    /// Maximum AAD length accepted by [`encrypt_hybrid`] /
    /// [`decrypt_hybrid`]. 64 KiB is well above any realistic transport-
    /// header or request-ID payload while keeping the per-call HKDF
    /// `info` payload small enough that the length-prefixed concatenation
    /// stays in a single page.
    pub const MAX_AAD_LEN: usize = 64 * 1024;

    /// Construct with the canonical `HYBRID_ENCRYPTION_INFO` domain
    /// separator (recommended) and the supplied AAD.
    #[must_use]
    pub fn with_aad(aad: Vec<u8>) -> Self {
        Self { info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(), aad }
    }

    /// Construct with an explicit `info` domain separator. Reserved for
    /// callers that have registered their own label in
    /// [`crate::types::domains`] — passing an arbitrary string here risks
    /// collision with another protocol and breaks Pattern 7.
    ///
    /// The `info` argument is `&'static [u8]` deliberately: it forces
    /// callers to declare the label as a `pub const &[u8]` somewhere
    /// (typically `domains.rs`), which is the grep-able audit checkpoint.
    #[must_use]
    pub fn with_explicit_info(info: &'static [u8], aad: Vec<u8>) -> Self {
        Self { info: info.to_vec(), aad }
    }

    /// Read-only access to the `info` field for tests, debug printing, and
    /// per-call wire framing.
    #[must_use]
    pub fn info(&self) -> &[u8] {
        &self.info
    }
}

/// Public-key + KEM-ciphertext binding for the AEAD-key KDF.
///
/// Pattern 7 / HPKE §5.1 require the recipient public key, the
/// ephemeral public key, and the KEM ciphertext (`enc`) to be bound
/// into the *final* key-schedule KDF — not just the upstream KEM
/// combiner — so that key-substitution and KEM-rebinding attacks
/// against an as-yet-unknown future weakness in either component KEM
/// cannot produce the same AEAD key under a different `(recipient,
/// ephemeral, ct)` triple.
///
/// The combiner at [`crate::hybrid::kem_hybrid::derive_hybrid_shared_secret`]
/// already binds `static_pk` and `ephemeral_pk` into the shared
/// secret, so today the binding is *transitively* present. Re-binding
/// here is defense-in-depth: a future regression in the combiner that
/// silently dropped the PK mix would still be caught at this layer.
///
/// Borrowed slice fields (no allocation). Empty slices are accepted —
/// they just contribute zero-length length-prefixed segments — but
/// production callers (`encrypt_hybrid` / `decrypt_hybrid`) MUST
/// populate all three.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DerivationBinding<'a> {
    /// Recipient's static X25519 public key (the classical leg of the
    /// hybrid PK).
    pub recipient_static_pk: &'a [u8],
    /// Recipient's static ML-KEM public key (the PQ leg of the hybrid
    /// PK). bound here so the AEAD KDF
    /// info channel-binds the FULL hybrid recipient identity, not just
    /// its X25519 half. The previous binding only bound X25519
    /// directly; the ML-KEM half was bound only transitively via the
    /// `kem_ciphertext`. An adversary who broke ML-KEM IND-CCA2
    /// substitution would have gotten through the AEAD KDF binding
    /// even with the recipient_static_pk leg intact.
    /// BREAKING CHANGE: 0.7.x hybrid ciphertexts cannot be decrypted
    /// by 0.8.x and vice versa. See CHANGELOG.
    pub recipient_ml_kem_pk: &'a [u8],
    /// Sender's ephemeral public key produced by `kem_hybrid::encapsulate`.
    /// For the hybrid KEM this is the X25519 ephemeral PK.
    pub ephemeral_pk: &'a [u8],
    /// Raw ML-KEM ciphertext (`enc`) produced by `kem_hybrid::encapsulate`.
    pub kem_ciphertext: &'a [u8],
}

impl<'a> DerivationBinding<'a> {
    /// Empty binding (no PK / `enc` mixing). Reserved for tests that
    /// exercise `derive_encryption_key` in isolation without a real
    /// KEM round-trip. Production code must use a fully-populated
    /// binding constructed by `encrypt_hybrid` / `decrypt_hybrid`.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            recipient_static_pk: &[],
            recipient_ml_kem_pk: &[],
            ephemeral_pk: &[],
            kem_ciphertext: &[],
        }
    }
}

/// HPKE-style key derivation for hybrid encryption.
///
/// Delegates to the primitives HKDF wrapper (`primitives::kdf::hkdf::hkdf`)
/// which is backed by aws-lc-rs HMAC-SHA256 under the hood, so all callers share
/// the same FIPS-validated implementation, zeroization guarantees, and
/// instrumentation.
///
/// # Security
///
/// The context's AAD is bound in two places: (1) mixed into the HKDF info
/// parameter here, so different AAD values derive different encryption keys,
/// and (2) passed to AES-GCM as authenticated data during encrypt/decrypt.
/// This dual binding ensures AAD provides both key separation and ciphertext
/// authentication.
///
/// `binding` mixes the recipient public key, the ephemeral public key, and
/// the raw KEM ciphertext into the same HKDF info — see
/// [`DerivationBinding`] for the rationale (Pattern 7 / HPKE §5.1).
///
/// # Errors
///
/// Returns an error if the shared secret is not exactly 32 or 64 bytes,
/// or if HKDF expansion fails.
pub fn derive_encryption_key(
    shared_secret: &[u8],
    context: &HybridEncryptionContext,
    binding: &DerivationBinding<'_>,
) -> Result<Zeroizing<[u8; 32]>, HybridEncryptionError> {
    if shared_secret.len() != 32 && shared_secret.len() != 64 {
        return Err(HybridEncryptionError::KdfError(
            "Shared secret must be 32 bytes (ML-KEM) or 64 bytes (hybrid)".to_string(),
        ));
    }

    // Reject inputs that would overflow our length prefixes. u32 covers every
    // realistic field, and the early check keeps the `as u32` conversions
    // below non-truncating.
    let oversize = context.info.len() > u32::MAX as usize
        || context.aad.len() > u32::MAX as usize
        || binding.recipient_static_pk.len() > u32::MAX as usize
        || binding.recipient_ml_kem_pk.len() > u32::MAX as usize
        || binding.ephemeral_pk.len() > u32::MAX as usize
        || binding.kem_ciphertext.len() > u32::MAX as usize;
    if oversize {
        return Err(HybridEncryptionError::KdfError(
            "HKDF info / aad / binding field exceeds 2^32 bytes".to_string(),
        ));
    }

    // Build a length-prefixed HKDF info payload to prevent canonicalization
    // collisions between the variable-length fields. Naive concatenation
    // `f1 || "||" || f2` is ambiguous when source data can contain the
    // separator bytes; length-prefixing is the standard fix.
    //
    // Construction is HPKE-inspired (RFC 9180 §5.1) but **NOT bit-compatible
    // with HPKE LabeledExtract**: HPKE uses `I2OSP(len, 2)` (2-byte big-
    // endian) length prefixes capped at 65 535 bytes. We use 4-byte big-
    // endian (`u32`) prefixes because `HybridEncryptionContext::aad` has a
    // `MAX_AAD_LEN = 64 KiB` ceiling that already touches HPKE's `u16` cap,
    // and `info` has no documented ceiling at all. A third party building
    // an interop derivation MUST mirror this 4-byte prefix layout — they
    // cannot copy HPKE LabeledExtract directly and expect the same `info`
    // blob.
    //
    // Wire layout (each `len: u32 BE` is followed by `len` bytes):
    //   [info_len][info]
    //   [aad_len][aad]
    //   [recipient_x25519_pk_len][recipient_x25519_pk]   ── Pattern 7 / channel binding
    //   [recipient_ml_kem_pk_len][recipient_ml_kem_pk]   ── fix M4/M19
    //   [ephemeral_pk_len][ephemeral_pk]                 ── ditto
    //   [kem_ct_len][kem_ct]                             ── ditto
    //
    // Order is fixed; reordering or omitting any segment is a
    // wire-format break. The ml-kem leg is positioned before the
    // ephemeral pk so that pre-existing v1 wire-format readers (which
    // expected ephemeral after the X25519 leg) fail closed instead of
    // silently misinterpreting a longer payload.
    let segments: [&[u8]; 6] = [
        &context.info,
        &context.aad,
        binding.recipient_static_pk,
        binding.recipient_ml_kem_pk,
        binding.ephemeral_pk,
        binding.kem_ciphertext,
    ];
    let total: usize = segments
        .iter()
        .try_fold(0usize, |acc, s| acc.checked_add(4)?.checked_add(s.len()))
        .ok_or_else(|| {
            HybridEncryptionError::KdfError("HKDF info payload size overflow".to_string())
        })?;
    let mut info = Vec::with_capacity(total);
    for segment in segments {
        // Safe: bounds-checked above — `try_from` cannot fail after the
        // u32::MAX guards, but we use it to silence
        // `cast_possible_truncation` and prove the non-truncation
        // invariant to the compiler.
        let len_u32 = u32::try_from(segment.len()).map_err(|_e| {
            HybridEncryptionError::KdfError("HKDF info segment exceeds 2^32 bytes".to_string())
        })?;
        info.extend_from_slice(&len_u32.to_be_bytes());
        info.extend_from_slice(segment);
    }

    // HKDF-SHA256 via primitives wrapper (backed by aws-lc-rs HMAC).
    // Zero-length salt (`None`) matches HPKE (RFC 9180 §5.1). RFC 5869 §2.2
    // permits zero salt when IKM is already uniformly random; `shared_secret`
    // here is a KEM/DH output (32 B ML-KEM or 64 B ML-KEM || ECDH), so
    // Extract's salt is not doing entropy extraction. Domain separation,
    // AAD/context binding, and PK / ciphertext binding all live in `info`.
    let hkdf_result = hkdf(shared_secret, None, Some(&info), 32).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_DERIVE_KEY, "HKDF failed");
        HybridEncryptionError::KdfError("KDF failed".to_string())
    })?;

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(hkdf_result.expose_secret());
    Ok(key)
}

/// True hybrid encryption using ML-KEM-768 + X25519 + AES-256-GCM.
///
/// This function performs real hybrid key encapsulation (combining post-quantum
/// ML-KEM with classical X25519 ECDH via HKDF) before AES-256-GCM encryption.
/// Security holds if *either* ML-KEM or X25519 remains secure.
///
/// # Security
///
/// - Hybrid security: breaks only if BOTH ML-KEM and X25519 are compromised
/// - AES-256-GCM nonce generated internally from OS CSPRNG (SP 800-38D §8.2)
/// - HKDF dual-PRF combiner with domain separation (SP 800-56C)
/// - All shared secrets are zeroized after key derivation
///
/// # Errors
///
/// Returns an error if:
/// - Hybrid KEM encapsulation fails
/// - Key derivation fails
/// - AES-GCM encryption fails
pub fn encrypt_hybrid(
    hybrid_pk: &HybridKemPublicKey,
    plaintext: &[u8],
    context: Option<&HybridEncryptionContext>,
) -> Result<HybridCiphertext, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Encrypt-side opacity (defense-in-depth per Pattern 6). Opaque returned
    // error; tracing::debug! keeps the specific reason for operator debugging.
    let opaque_kem = || HybridEncryptionError::KemError("encapsulation failed".to_string());
    let opaque_enc = || HybridEncryptionError::EncryptionError("encryption failed".to_string());

    // DoS bound on AAD: rejected up-front before any KEM / KDF / AEAD
    // work runs, so an oversized AAD cannot consume cryptographic budget.
    // See `HybridEncryptionContext::MAX_AAD_LEN`.
    // collapse to opaque InvalidInput (matching decrypt-side opacity at
    // `decrypt_hybrid:538`) so the encrypt path doesn't disclose the
    // observed AAD length and the cap as a probable-bound oracle. Source-
    // side cause goes to `tracing::debug!` for operator debugging.
    if ctx.aad.len() > HybridEncryptionContext::MAX_AAD_LEN {
        log_crypto_operation_error!(op::HYBRID_ENCRYPT, "AAD exceeds MAX_AAD_LEN");
        // Use the same opaque envelope as KEM / AEAD failures so the
        // returned error variant cannot be used by an adversary varying
        // wire-supplied AAD to distinguish "AAD-overflow" from
        // "encapsulation failed" / "encryption failed". Source-side
        // cause is preserved in the `tracing::debug!` line above.
        return Err(opaque_enc());
    }

    // Hybrid KEM encapsulation (ML-KEM-768 + X25519 ECDH + HKDF)
    let encapsulated = kem_hybrid::encapsulate(hybrid_pk).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_ENCRYPT, "KEM encapsulation failed");
        opaque_kem()
    })?;

    // Derive AES-256 encryption key from 64-byte hybrid shared secret.
    // Pattern 7 / HPKE: bind recipient PK + ephemeral PK + KEM ciphertext
    // into the HKDF info, on top of the upstream combiner's binding.
    // bind ML-KEM PK explicitly into the
    // AEAD KDF info, not just transitively through the KEM ciphertext.
    let binding = DerivationBinding {
        recipient_static_pk: hybrid_pk.ecdh_pk(),
        recipient_ml_kem_pk: hybrid_pk.ml_kem_pk(),
        ephemeral_pk: encapsulated.ecdh_pk(),
        kem_ciphertext: encapsulated.ml_kem_ct(),
    };
    let encryption_key = derive_encryption_key(encapsulated.expose_secret(), ctx, &binding)?;

    // Generate random nonce for AES-GCM via the primitives layer.
    let nonce_bytes = AesGcm256::generate_nonce();

    // AES-256-GCM via primitives wrapper.
    let cipher = AesGcm256::new(&*encryption_key).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_ENCRYPT, "AES-256 init failed");
        opaque_enc()
    })?;
    let (ciphertext, tag) =
        cipher.encrypt(&nonce_bytes, plaintext, Some(&ctx.aad)).map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_ENCRYPT, "AES-GCM seal failed");
            opaque_enc()
        })?;

    Ok(HybridCiphertext::new(
        encapsulated.ml_kem_ct().to_vec(),
        encapsulated.ecdh_pk().to_vec(),
        ciphertext,
        nonce_bytes.to_vec(),
        tag.to_vec(),
    ))
}

/// True hybrid decryption using ML-KEM + X25519 + AES-256-GCM.
///
/// This function performs real hybrid key decapsulation (ML-KEM decapsulation +
/// X25519 ECDH agreement, combined via HKDF) before AES-256-GCM decryption.
/// The ML-KEM security level is determined by the secret key.
///
/// # Errors
///
/// Returns an error if:
/// - The ciphertext components have invalid lengths
/// - Hybrid KEM decapsulation fails
/// - Key derivation fails
/// - AES-GCM decryption or authentication fails
pub fn decrypt_hybrid(
    hybrid_sk: &HybridKemSecretKey,
    ciphertext: &HybridCiphertext,
    context: Option<&HybridEncryptionContext>,
) -> Result<Zeroizing<Vec<u8>>, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Pattern 6: every adversary-reachable failure path collapses to the
    // same opaque returned error. The KEM-ciphertext length check used to
    // be its own InvalidInput variant naming `expected_ct_size` — that
    // disclosed the recipient's ML-KEM security level (512 / 768 / 1024)
    // by error-message inspection. Now folded into the opaque block with
    // an internal trace under `op::HYBRID_DECRYPT` so operators can
    // correlate via `correlation_id`. Nonce / tag / ECDH-PK lengths are
    // also folded for consistency, even though they are public protocol
    // constants — uniform handling removes the variant-discrimination
    // oracle entirely.
    let opaque = || HybridEncryptionError::DecryptionError("decryption failed".to_string());

    // DoS bound on AAD: rejected up-front before any KEM / KDF / AEAD
    // work runs. Symmetric with the encrypt-side check; folded into the
    // opaque path so an adversary cannot probe for an AAD-length oracle.
    if ctx.aad.len() > HybridEncryptionContext::MAX_AAD_LEN {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "AAD exceeds MAX_AAD_LEN");
        return Err(opaque());
    }

    // Validate ciphertext shape — opaque (no `expected_ct_size` leak) +
    // per-stage internal trace.
    let expected_ct_size = hybrid_sk.security_level().ciphertext_size();
    if ciphertext.kem_ciphertext().len() != expected_ct_size {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "KEM ciphertext length mismatch");
        return Err(opaque());
    }
    if ciphertext.ecdh_ephemeral_pk().len() != 32 {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "ECDH ephemeral PK length invalid");
        return Err(opaque());
    }
    if ciphertext.nonce().len() != 12 {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "AES-GCM nonce length invalid");
        return Err(opaque());
    }
    if ciphertext.tag().len() != 16 {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "AES-GCM tag length invalid");
        return Err(opaque());
    }

    // Hybrid KEM decapsulation (ML-KEM + X25519 ECDH + HKDF). The
    // `_from_parts` entry point takes the two ciphertext halves
    // directly — building a full `EncapsulatedKey` here would require
    // a placeholder shared-secret value that `decapsulate` never reads.
    let shared_secret = kem_hybrid::decapsulate_from_parts(
        hybrid_sk,
        ciphertext.kem_ciphertext(),
        ciphertext.ecdh_ephemeral_pk(),
    )
    .map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "KEM decapsulation failed");
        opaque()
    })?;

    // Derive AES-256 encryption key from 64-byte hybrid shared secret.
    // Pattern 7 / HPKE: bind recipient PK + ephemeral PK + KEM ciphertext
    // into the HKDF info (must match the encrypt-side binding exactly).
    let recipient_static_pk = hybrid_sk.ecdh_public_key_bytes();
    // mirror the encrypt-side ML-KEM
    // PK binding. The ML-KEM PK is reconstructible from the SK via the
    // FIPS 203 §6.1 layout; `ml_kem_public_key_bytes()` exposes the
    // embedded `ek` slice.
    let recipient_ml_kem_pk = hybrid_sk.ml_kem_pk_bytes();
    let binding = DerivationBinding {
        recipient_static_pk: &recipient_static_pk,
        recipient_ml_kem_pk: &recipient_ml_kem_pk,
        ephemeral_pk: ciphertext.ecdh_ephemeral_pk(),
        kem_ciphertext: ciphertext.kem_ciphertext(),
    };
    let encryption_key = derive_encryption_key(shared_secret.expose_secret(), ctx, &binding)
        .map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_DECRYPT, "HKDF key derivation failed");
            opaque()
        })?;

    let nonce_bytes: [u8; NONCE_LEN] = ciphertext.nonce().try_into().map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "nonce length != 12");
        opaque()
    })?;
    let tag_bytes: [u8; TAG_LEN] = ciphertext.tag().try_into().map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "tag length != 16");
        opaque()
    })?;

    // AES-256-GCM via primitives wrapper.
    let cipher = AesGcm256::new(&*encryption_key).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_DECRYPT, "AES-256 init failed");
        opaque()
    })?;
    // `cipher.decrypt` already returns `Zeroizing<Vec<u8>>` — propagate directly.
    let plaintext = cipher
        .decrypt(&nonce_bytes, ciphertext.symmetric_ciphertext(), &tag_bytes, Some(&ctx.aad))
        .map_err(|_aead_err| {
            log_crypto_operation_error!(op::HYBRID_DECRYPT, "AEAD authentication failed");
            opaque()
        })?;

    Ok(plaintext)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_properties_are_deterministic_and_unique() {
        let shared_secret = vec![1u8; 32];
        let context1 =
            HybridEncryptionContext { info: b"Context1".to_vec(), aad: b"AAD1".to_vec() };
        let context2 =
            HybridEncryptionContext { info: b"Context2".to_vec(), aad: b"AAD2".to_vec() };

        let key1 =
            derive_encryption_key(&shared_secret, &context1, &DerivationBinding::empty()).unwrap();
        let key2 =
            derive_encryption_key(&shared_secret, &context2, &DerivationBinding::empty()).unwrap();

        // Different contexts should produce different keys
        assert_ne!(key1, key2, "Different contexts should produce different keys");

        // Same context should produce same key (deterministic)
        let key1_again =
            derive_encryption_key(&shared_secret, &context1, &DerivationBinding::empty()).unwrap();
        assert_eq!(key1, key1_again, "Key derivation should be deterministic");

        // Test invalid shared secret length
        let invalid_secret = vec![1u8; 31]; // Wrong length
        let result = derive_encryption_key(&invalid_secret, &context1, &DerivationBinding::empty());
        assert!(result.is_err(), "Should reject invalid shared secret length");

        // Test 64-byte hybrid shared secret is accepted
        let hybrid_secret = vec![1u8; 64];
        let result = derive_encryption_key(&hybrid_secret, &context1, &DerivationBinding::empty());
        assert!(result.is_ok(), "Should accept 64-byte hybrid shared secret");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_roundtrip() {
        // Generate hybrid keypair (ML-KEM-768 + X25519)
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Hello, true hybrid encryption!";
        let context = HybridEncryptionContext::default();

        // Encrypt with true hybrid (ML-KEM + X25519 + HKDF + AES-GCM)
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&context)).unwrap();

        assert_eq!(ct.kem_ciphertext().len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
        assert_eq!(ct.ecdh_ephemeral_pk().len(), 32, "X25519 ephemeral PK should be 32 bytes");
        assert!(!ct.symmetric_ciphertext().is_empty(), "Symmetric ciphertext should not be empty");
        assert_eq!(ct.nonce().len(), 12, "Nonce should be 12 bytes");
        assert_eq!(ct.tag().len(), 16, "Tag should be 16 bytes");

        // Decrypt with true hybrid
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&context)).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decrypted text should match original"
        );
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_with_aad_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Secret message with AAD";
        let aad = b"Additional authenticated data";
        let context = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: aad.to_vec(),
        };

        // Encrypt with AAD
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&context)).unwrap();

        // Decrypt with correct AAD
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&context)).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decryption with correct AAD should succeed"
        );

        // Decrypt with wrong AAD should fail
        let wrong_context = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: b"Wrong AAD".to_vec(),
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&wrong_context));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_different_ciphertexts_for_same_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Same plaintext, different ciphertexts";

        let ct1 = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let ct2 = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();

        // Ciphertexts should differ (randomized encapsulation + nonce)
        assert_ne!(ct1.kem_ciphertext(), ct2.kem_ciphertext());
        assert_ne!(ct1.ecdh_ephemeral_pk(), ct2.ecdh_ephemeral_pk());

        // Both should decrypt correctly
        let dec1 = decrypt_hybrid(&hybrid_sk, &ct1, None).unwrap();
        let dec2 = decrypt_hybrid(&hybrid_sk, &ct2, None).unwrap();
        assert_eq!(dec1.as_slice(), plaintext.as_slice());
        assert_eq!(dec2.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_error_display_variants_produce_nonempty_strings_fails() {
        let kem_err = HybridEncryptionError::KemError("kem fail".to_string());
        assert!(kem_err.to_string().contains("kem fail"));

        let enc_err = HybridEncryptionError::EncryptionError("enc fail".to_string());
        assert!(enc_err.to_string().contains("enc fail"));

        let dec_err = HybridEncryptionError::DecryptionError("dec fail".to_string());
        assert!(dec_err.to_string().contains("dec fail"));

        let kdf_err = HybridEncryptionError::KdfError("kdf fail".to_string());
        assert!(kdf_err.to_string().contains("kdf fail"));

        let input_err = HybridEncryptionError::InvalidInput("bad input".to_string());
        assert!(input_err.to_string().contains("bad input"));

        let key_err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 };
        let msg = key_err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_error_clone_round_trips() {
        let err1 = HybridEncryptionError::KemError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1.to_string(), err2.to_string());
        assert!(matches!(err2, HybridEncryptionError::KemError(_)));

        let err3 = HybridEncryptionError::KemError("different".to_string());
        assert_ne!(err1.to_string(), err3.to_string());
    }

    #[test]
    fn test_hybrid_ciphertext_clone_debug_work_correctly_succeeds() {
        let ct = HybridCiphertext::new(
            vec![1, 2, 3],
            vec![4, 5],
            vec![6, 7, 8],
            vec![9; 12],
            vec![10; 16],
        );
        let ct2 = ct.clone();
        assert_eq!(ct.kem_ciphertext(), ct2.kem_ciphertext());
        assert_eq!(ct.ecdh_ephemeral_pk(), ct2.ecdh_ephemeral_pk());

        let debug_str = format!("{:?}", ct);
        assert!(debug_str.contains("HybridCiphertext"));
    }

    #[test]
    fn test_encryption_context_default_sets_expected_fields_succeeds() {
        let ctx = HybridEncryptionContext::default();
        assert_eq!(ctx.info, crate::types::domains::HYBRID_ENCRYPTION_INFO);
        assert!(ctx.aad.is_empty());
    }

    #[test]
    fn test_encryption_context_clone_debug_work_correctly_succeeds() {
        let ctx =
            HybridEncryptionContext { info: b"custom-info".to_vec(), aad: b"custom-aad".to_vec() };
        let ctx2 = ctx.clone();
        assert_eq!(ctx.info, ctx2.info);
        assert_eq!(ctx.aad, ctx2.aad);

        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("HybridEncryptionContext"));
    }

    #[test]
    fn test_derive_key_invalid_lengths_fail_fails() {
        let ctx = HybridEncryptionContext::default();

        // Too short (31 bytes)
        assert!(derive_encryption_key(&[0u8; 31], &ctx, &DerivationBinding::empty()).is_err());

        // Too long (65 bytes)
        assert!(derive_encryption_key(&[0u8; 65], &ctx, &DerivationBinding::empty()).is_err());

        // 1 byte
        assert!(derive_encryption_key(&[0u8; 1], &ctx, &DerivationBinding::empty()).is_err());

        // Empty
        assert!(derive_encryption_key(&[], &ctx, &DerivationBinding::empty()).is_err());

        // 33 bytes (between valid sizes)
        assert!(derive_encryption_key(&[0u8; 33], &ctx, &DerivationBinding::empty()).is_err());
    }

    #[test]
    fn test_derive_key_different_secrets_produce_different_keys_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];

        let key_a = derive_encryption_key(&secret_a, &ctx, &DerivationBinding::empty()).unwrap();
        let key_b = derive_encryption_key(&secret_b, &ctx, &DerivationBinding::empty()).unwrap();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_64_byte_hybrid_secret_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret = [42u8; 64];
        let key = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        assert_eq!(key.len(), 32);

        // Deterministic
        let key2 = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_decrypt_hybrid_invalid_kem_ct_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 500],
            vec![2u8; 32],
            vec![3u8; 64],
            vec![4u8; 12],
            vec![5u8; 16],
        ); // Wrong: KEM CT should be 1088
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Pattern 6 (#51): decrypt collapses size-shape mismatches into the
        // opaque DecryptionError to avoid leaking which component was malformed.
        assert!(matches!(err, HybridEncryptionError::DecryptionError(_)));
    }

    #[test]
    fn test_decrypt_hybrid_invalid_ecdh_pk_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![2u8; 16],
            vec![3u8; 64],
            vec![4u8; 12],
            vec![5u8; 16],
        ); // Wrong: ECDH PK should be 32
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Pattern 6 (#51): see test_decrypt_hybrid_invalid_kem_ct_length_fails note.
        assert!(matches!(err, HybridEncryptionError::DecryptionError(_)));
    }

    #[test]
    fn test_decrypt_hybrid_invalid_nonce_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![2u8; 32],
            vec![3u8; 64],
            vec![4u8; 8],
            vec![5u8; 16],
        ); // Wrong: nonce should be 12
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_invalid_tag_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![2u8; 32],
            vec![3u8; 64],
            vec![4u8; 12],
            vec![5u8; 10],
        ); // Wrong: tag should be 16
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_tampered_ciphertext_fails() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Test message for tampering";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();

        // Tamper with symmetric ciphertext
        let mut tampered = ct.clone();
        if let Some(byte) = tampered.symmetric_ciphertext_mut().first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_hybrid(&hybrid_sk, &tampered, None).is_err());

        // Tamper with tag
        let mut tampered_tag = ct;
        if let Some(byte) = tampered_tag.tag.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_hybrid(&hybrid_sk, &tampered_tag, None).is_err());
    }

    #[test]
    fn test_encrypt_hybrid_empty_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_hybrid_large_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = vec![0xABu8; 10_000];
        let ct = encrypt_hybrid(&hybrid_pk, &plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_hybrid_with_none_context_uses_default_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Default context test";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_hybrid_with_none_context_uses_default_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let default_ctx = HybridEncryptionContext::default();
        let ct = encrypt_hybrid(&hybrid_pk, b"ctx test", Some(&default_ctx)).unwrap();
        // Decrypt with None context should also use default
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), b"ctx test");
    }

    // ========================================================================
    // Additional coverage: derive_encryption_key and error paths
    // ========================================================================

    #[test]
    fn test_derive_encryption_key_with_64_byte_secret_succeeds() {
        let secret = [0xAA; 64]; // Hybrid 64-byte shared secret
        let ctx = HybridEncryptionContext::default();
        let key = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_encryption_key_invalid_length_fails() {
        let ctx = HybridEncryptionContext::default();
        // 16 bytes is neither 32 nor 64
        let result = derive_encryption_key(&[0u8; 16], &ctx, &DerivationBinding::empty());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_derive_encryption_key_is_deterministic() {
        let secret = [0xBB; 32];
        let ctx = HybridEncryptionContext::default();
        let k1 = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx, &DerivationBinding::empty()).unwrap();
        assert_eq!(k1, k2, "Same inputs must produce same key");
    }

    #[test]
    fn test_derive_encryption_key_different_contexts_produce_different_keys_succeeds() {
        let secret = [0xCC; 32];
        let ctx1 = HybridEncryptionContext { info: b"ctx1".to_vec(), aad: vec![] };
        let ctx2 = HybridEncryptionContext { info: b"ctx2".to_vec(), aad: vec![] };
        let k1 = derive_encryption_key(&secret, &ctx1, &DerivationBinding::empty()).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx2, &DerivationBinding::empty()).unwrap();
        assert_ne!(k1, k2, "Different contexts must produce different keys");
    }

    #[test]
    fn test_derive_encryption_key_with_aad_succeeds() {
        let secret = [0xDD; 32];
        let ctx_no_aad = HybridEncryptionContext::default();
        let ctx_with_aad = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: b"extra-data".to_vec(),
        };
        let k1 = derive_encryption_key(&secret, &ctx_no_aad, &DerivationBinding::empty()).unwrap();
        let k2 =
            derive_encryption_key(&secret, &ctx_with_aad, &DerivationBinding::empty()).unwrap();
        assert_ne!(k1, k2, "Different AAD must produce different keys");
    }

    #[test]
    fn test_encrypt_hybrid_custom_context_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ctx = HybridEncryptionContext {
            info: b"custom-app-info".to_vec(),
            aad: b"custom-aad".to_vec(),
        };

        let plaintext = b"Custom context encryption";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&ctx)).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_hybrid_wrong_context_fails() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ctx1 = HybridEncryptionContext { info: b"context-1".to_vec(), aad: b"aad-1".to_vec() };
        let ctx2 = HybridEncryptionContext { info: b"context-2".to_vec(), aad: b"aad-2".to_vec() };

        let ct = encrypt_hybrid(&hybrid_pk, b"test", Some(&ctx1)).unwrap();
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx2));
        assert!(result.is_err(), "Wrong context must fail decryption");
    }

    #[test]
    fn test_hybrid_encryption_error_display_all_variants_are_nonempty_fails() {
        let errors = vec![
            HybridEncryptionError::KemError("kem".into()),
            HybridEncryptionError::EncryptionError("enc".into()),
            HybridEncryptionError::DecryptionError("dec".into()),
            HybridEncryptionError::InvalidInput("inp".into()),
            HybridEncryptionError::KdfError("kdf".into()),
            HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 },
        ];
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
        }
    }
}
