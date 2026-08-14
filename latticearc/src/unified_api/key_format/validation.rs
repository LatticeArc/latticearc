//! `PortableKey` validation: structural consistency (`validate`),
//! informational-expiry gating (`validate_with_expiry*`), and the
//! encrypted-envelope / composite-key-length shape checks shared with
//! `encryption` and `conversions`.

use super::{
    AES_GCM_AEAD_ID, AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, ENCRYPTED_ENVELOPE_VERSION, KeyAlgorithm,
    KeyData, KeyType, PBKDF2_DEFAULT_ITERATIONS, PBKDF2_KDF_ID, PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS, PBKDF2_MIN_SALT_LEN, PortableKey,
};
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::serialization::decode_b64_opaque;
use chrono::{DateTime, Utc};

impl PortableKey {
    // --- Validation ---

    /// Validate internal consistency.
    ///
    /// Checks:
    /// - Format version matches [`CURRENT_VERSION`](Self::CURRENT_VERSION)
    /// - Symmetric algorithms (`aes-256`, `chacha20`) require `KeyType::Symmetric`
    /// - Hybrid algorithms require composite `KeyData`
    /// - Non-hybrid algorithms require single `KeyData`
    /// - Base64 key data decodes successfully
    ///
    /// # Errors
    /// Returns `CoreError::InvalidKey` on validation failure.
    pub fn validate(&self) -> Result<()> {
        // Version check — reject keys serialized by future or incompatible versions
        if self.version != Self::CURRENT_VERSION {
            return Err(CoreError::InvalidKey(format!(
                "Unsupported key format version {}, expected {}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }

        // Metadata caps: enforce on every deserialization path so an
        // attacker-supplied document cannot smuggle a 100k-entry map
        // past the 1 MiB whole-document gate. `serde_json::Value` is
        // recursive — even a small JSON string can build a much larger
        // heap tree — and the metadata is hashed into the AAD on
        // every encrypted-key load.
        if self.metadata.len() > Self::MAX_METADATA_ENTRIES {
            return Err(CoreError::InvalidKey(format!(
                "metadata entry count {} exceeds maximum {}",
                self.metadata.len(),
                Self::MAX_METADATA_ENTRIES
            )));
        }
        for (key, value) in &self.metadata {
            if key.len() > Self::MAX_METADATA_KEY_LEN {
                return Err(CoreError::InvalidKey(format!(
                    "metadata key length {} exceeds maximum {}",
                    key.len(),
                    Self::MAX_METADATA_KEY_LEN
                )));
            }
            let value_len = serde_json::to_string(value).map(|s| s.len()).map_err(|e| {
                CoreError::SerializationError(format!(
                    "metadata value re-serialization failed: {e}"
                ))
            })?;
            if value_len > Self::MAX_METADATA_VALUE_JSON_LEN {
                // `key` is an attacker-controlled `String` from the
                // deserialized BTreeMap. Surface only its length (not the
                // value) so a tampered key file can't be used to fingerprint
                // which key-name tripped the cap.
                return Err(CoreError::InvalidKey(format!(
                    "metadata value JSON length {} for key (len={}) exceeds maximum {}",
                    value_len,
                    key.len(),
                    Self::MAX_METADATA_VALUE_JSON_LEN
                )));
            }
        }

        // Symmetric algorithm ↔ key type
        if self.algorithm.is_symmetric() && self.key_type != KeyType::Symmetric {
            return Err(CoreError::InvalidKey(format!(
                "Algorithm {:?} requires KeyType::Symmetric, got {:?}",
                self.algorithm, self.key_type
            )));
        }
        if !self.algorithm.is_symmetric() && self.key_type == KeyType::Symmetric {
            return Err(CoreError::InvalidKey(format!(
                "KeyType::Symmetric is not valid for algorithm {:?}",
                self.algorithm
            )));
        }

        // Hybrid ↔ composite key data (encrypted variant is opaque — skip this check).
        match (&self.key_data, self.algorithm.is_hybrid()) {
            (KeyData::Composite { .. }, false) => {
                return Err(CoreError::InvalidKey(format!(
                    "Non-hybrid algorithm {:?} must use single key data",
                    self.algorithm
                )));
            }
            (KeyData::Single { .. }, true) => {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid algorithm {:?} must use composite key data",
                    self.algorithm
                )));
            }
            _ => {}
        }

        // Verify base64 decodes / envelope shape
        match &self.key_data {
            KeyData::Single { raw } => {
                let _ = decode_b64_opaque(raw, "validate.single")?;
            }
            KeyData::Composite { pq, classical } => {
                let pq_bytes = decode_b64_opaque(pq, "validate.composite.pq")?;
                let classical_bytes = decode_b64_opaque(classical, "validate.composite.classical")?;
                // validate component sizes for hybrid keys.
                // The composite arm previously only verified that
                // base64 decoded — a truncated PQ component or a
                // wrong-level keyfile slipped past `validate()` and
                // failed downstream with less-informative errors. We
                // bound the components against the expected sizes for
                // the (algorithm, key_type) pair so the failure point
                // is the load site, not three layers deep.
                //
                // Sizes are upper bounds: secret keys hold a seed +
                // pk; we accept anything from `min_seed` (32) through
                // the full secret-key size. Public-key composite
                // values must match the level's pk size exactly.
                Self::validate_composite_lengths(
                    self.algorithm,
                    pq_bytes.len(),
                    classical_bytes.len(),
                )?;
            }
            KeyData::Encrypted { enc, kdf, kdf_iterations, kdf_salt, aead, nonce, ciphertext } => {
                Self::validate_encrypted_envelope_fields(
                    *enc,
                    kdf,
                    *kdf_iterations,
                    kdf_salt,
                    aead,
                    nonce,
                    ciphertext,
                )?;
            }
        }

        Ok(())
    }

    /// Validate this key AND reject it if it has expired at `now`.
    ///
    /// # M4 fix
    ///
    /// [`validate`](Self::validate) intentionally **does not** consult
    /// `not_after` — that's a documented design choice ("informational
    /// lifecycle field") so that consumers loading a possibly-expired key
    /// for inspection or migration don't get failed at parse time. The
    /// auditor flagged the absence of any "is this key safe to USE right
    /// now?" gate as a footgun: a captured-but-expired key file is
    /// indistinguishable from a fresh one to anyone calling `validate()`.
    ///
    /// This helper is the explicit gate. Callers about to perform a crypto
    /// operation with the key should route through `validate_with_expiry`
    /// instead of `validate`. Callers loading a key for reporting,
    /// migration, or expiry-aware lifecycle handling continue to use
    /// `validate` and check [`is_expired_at`](Self::is_expired_at)
    /// themselves.
    ///
    /// `now` is passed explicitly so the call is testable without freezing
    /// the system clock and so determinism is preserved on the verify
    /// path. Pass `chrono::Utc::now()` from production callers.
    ///
    /// # Errors
    ///
    /// Returns the existing `validate()` errors on structural failures, or
    /// `CoreError::InvalidKey("key has expired")` if `now >= not_after`.
    /// The "expired" error is intentionally opaque: an attacker who can
    /// see the error variant could otherwise binary-search the `not_after`
    /// timestamp off-line via repeated calls with different `now` values.
    pub fn validate_with_expiry(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate()?;
        if self.is_expired_at(now) {
            return Err(CoreError::InvalidKey("key has expired".to_string()));
        }
        Ok(())
    }

    /// Wall-clock-anchored variant of [`Self::validate_with_expiry`]. Routes every
    /// key-extraction method on this type (`to_hybrid_public_key`,
    /// `to_hybrid_secret_key`, `to_hybrid_sig_public_key`,
    /// `to_hybrid_sig_secret_key`) through the expiry gate before the
    /// returned typed key escapes into a sign / encrypt / agree path. Reads
    /// `Utc::now()` once at call time so the gate can't be bypassed by a
    /// caller that holds a stale `DateTime<Utc>`.
    ///
    /// The expiry-aware gate is intentionally NOT folded into
    /// [`validate`](Self::validate): a tool inspecting an expired key for
    /// migration or reporting purposes must still be able to load it. The
    /// boundary is "loaded ≠ usable" — `validate()` accepts expired keys,
    /// `validate_with_expiry_now()` rejects them, and only the latter sits
    /// in the critical path before extracted key material reaches crypto.
    ///
    /// # Errors
    ///
    /// Forwards [`Self::validate_with_expiry`](Self::validate_with_expiry)'s
    /// errors: structural failures from [`validate`](Self::validate), or
    /// `CoreError::InvalidKey("key has expired")` if `not_after` is at or
    /// before the current wall clock.
    pub fn validate_with_expiry_now(&self) -> Result<()> {
        self.validate_with_expiry(Utc::now())
    }

    /// Validate an encrypted-envelope's metadata and base64-decodable sizes.
    ///
    /// Shared between [`Self::validate`] (which rejects malformed keys at
    /// load time) and [`Self::decrypt_with_passphrase`] (which uses this to
    /// defend against direct construction of an unvalidated encrypted
    /// variant). Does not verify the AEAD tag — that happens in
    /// `decrypt_with_passphrase` after key derivation.
    ///
    /// `pub(super)`: called cross-module from
    /// `key_format::encryption::PortableKey::decrypt_with_passphrase`.
    pub(super) fn validate_encrypted_envelope_fields(
        enc: u32,
        kdf: &str,
        kdf_iterations: u32,
        kdf_salt: &str,
        aead: &str,
        nonce: &str,
        ciphertext: &str,
    ) -> Result<()> {
        // Defense-in-depth: reject pathologically large field strings
        // BEFORE handing them to `base64::decode`. The 1 MiB
        // [`MAX_KEY_JSON_SIZE`] / [`MAX_KEY_CBOR_SIZE`] gate fires
        // earlier on the whole document, but post-decode allocation
        // amplifies (a 1 MiB base64 expands to ~750 KiB raw which is
        // then often re-allocated), and these per-field caps mirror
        // the pattern in `serialization.rs` for `EncryptedOutput`.
        // Generous slack vs. the cryptographic minimums lets future
        // schemes (e.g. larger PBKDF2 salts, XChaCha nonces) ship
        // without revisiting these constants.
        const MAX_KDF_SALT_B64: usize = 256; // raw cap is 64 B (PBKDF2)
        const MAX_NONCE_B64: usize = 64; // 12 B raw for AES-GCM
        const MAX_CIPHERTEXT_B64: usize = 1024 * 1024; // 1 MiB raw cap
        if kdf_salt.len() > MAX_KDF_SALT_B64 {
            return Err(CoreError::InvalidKey(format!(
                "kdf_salt base64 length {} exceeds maximum {MAX_KDF_SALT_B64}",
                kdf_salt.len()
            )));
        }
        if nonce.len() > MAX_NONCE_B64 {
            return Err(CoreError::InvalidKey(format!(
                "nonce base64 length {} exceeds maximum {MAX_NONCE_B64}",
                nonce.len()
            )));
        }
        if ciphertext.len() > MAX_CIPHERTEXT_B64 {
            return Err(CoreError::InvalidKey(format!(
                "ciphertext base64 length {} exceeds maximum {MAX_CIPHERTEXT_B64}",
                ciphertext.len()
            )));
        }
        // An envelope from an older schema version has a valid wire shape
        // but an older AEAD AAD layout, so authentication would fail
        // opaquely as "wrong passphrase". Detect it by version and emit a
        // distinct, actionable error instead.
        if enc < ENCRYPTED_ENVELOPE_VERSION {
            return Err(CoreError::InvalidKey(format!(
                "v{enc} encrypted-key envelope: the AEAD AAD layout changed in \
                 v{ENCRYPTED_ENVELOPE_VERSION}, so a v{enc} envelope cannot be \
                 decrypted by current code even with the correct passphrase. \
                 Re-protect the key: decrypt it with the release that wrote it, \
                 then re-encrypt with the current release."
            )));
        }
        if enc != ENCRYPTED_ENVELOPE_VERSION {
            return Err(CoreError::InvalidKey(format!(
                "Unsupported encrypted key envelope version {enc}, expected {ENCRYPTED_ENVELOPE_VERSION}",
            )));
        }
        // `kdf` and `aead` are attacker-controlled fields validated
        // before AEAD authentication. Echoing them in the typed error
        // would give an attacker a per-field fingerprint of which
        // check tripped; surface a fixed string and route the raw
        // value to `tracing::debug!` for operator visibility.
        if kdf != PBKDF2_KDF_ID {
            tracing::debug!(received = %kdf, expected = %PBKDF2_KDF_ID, "encrypted key envelope: unsupported KDF identifier");
            return Err(CoreError::InvalidKey("Unsupported KDF identifier".to_string()));
        }
        if aead != AES_GCM_AEAD_ID {
            tracing::debug!(received = %aead, expected = %AES_GCM_AEAD_ID, "encrypted key envelope: unsupported AEAD identifier");
            return Err(CoreError::InvalidKey("Unsupported AEAD identifier".to_string()));
        }
        if kdf_iterations < PBKDF2_MIN_ITERATIONS {
            return Err(CoreError::InvalidKey(format!(
                "PBKDF2 iteration count {kdf_iterations} below minimum {PBKDF2_MIN_ITERATIONS}",
            )));
        }
        if kdf_iterations > PBKDF2_MAX_ITERATIONS {
            // reject adversary-supplied envelopes with
            // pathological `kdf_iterations` before any HMAC-SHA256 rounds run.
            return Err(CoreError::InvalidKey(format!(
                "PBKDF2 iteration count {kdf_iterations} exceeds maximum {PBKDF2_MAX_ITERATIONS}",
            )));
        }
        // Warn when a loaded key uses fewer iterations than the current
        // OWASP-recommended default. The minimum (100k) is retained as a
        // hard floor for backwards compatibility with keys generated under
        // OWASP 2018 guidance; the default (600k) is OWASP 2023 for
        // HMAC-SHA256. Callers should re-protect keys below the default.
        //
        // Deduped per *distinct iteration count* per process: a mixed-fleet
        // operator loading key-A at 10k and key-B at 1k must see two
        // warnings (one per cohort), not one — otherwise the audit trail
        // hides the lower-iteration cohort behind the first cohort that
        // happened to trigger. Using `Mutex<HashSet<u32>>` here is fine
        // because key load is cold-path; the mutex is never contended on
        // a hot loop.
        if kdf_iterations < PBKDF2_DEFAULT_ITERATIONS {
            // Capacity cap prevents unbounded memory growth from an adversary
            // feeding distinct iteration-count keys. 256 distinct values is
            // far more than any realistic operator fleet (cohorts cluster
            // around OWASP guidance dates); beyond the cap we silence
            // further warnings — a single previously-emitted warning is
            // already enough audit signal that the cohort exists.
            const MAX_DISTINCT_ITERATION_COUNTS: usize = 256;
            static LOW_ITER_WARNED: std::sync::OnceLock<
                std::sync::Mutex<std::collections::HashSet<u32>>,
            > = std::sync::OnceLock::new();
            let table = LOW_ITER_WARNED.get_or_init(|| std::sync::Mutex::new(Default::default()));
            // Lock-poisoning here is non-fatal — emit the warning anyway,
            // since not warning is strictly worse than a duplicate warning.
            let mut seen = table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let should_warn = if seen.contains(&kdf_iterations) {
                false
            } else if seen.len() < MAX_DISTINCT_ITERATION_COUNTS {
                seen.insert(kdf_iterations);
                true
            } else {
                // Capacity reached — drop the new value silently. The
                // operator already has 256 prior warnings to act on; a
                // 257th cohort would not change the response.
                false
            };
            if should_warn {
                tracing::warn!(
                    kdf_iterations,
                    recommended = PBKDF2_DEFAULT_ITERATIONS,
                    "PBKDF2 iteration count is below the current OWASP recommendation; \
                     re-protect this key (decrypt + re-encrypt with passphrase) at the \
                     next opportunity."
                );
            }
        }
        let salt = decode_b64_opaque(kdf_salt, "validate.encrypted.kdf_salt")?;
        if salt.len() < PBKDF2_MIN_SALT_LEN {
            return Err(CoreError::InvalidKey(format!(
                "PBKDF2 salt length {} below minimum {PBKDF2_MIN_SALT_LEN}",
                salt.len(),
            )));
        }
        let nonce_bytes = decode_b64_opaque(nonce, "validate.encrypted.nonce")?;
        if nonce_bytes.len() != AES_GCM_NONCE_LEN {
            return Err(CoreError::InvalidKey(format!(
                "AES-GCM nonce length {} != {AES_GCM_NONCE_LEN}",
                nonce_bytes.len(),
            )));
        }
        let ct_bytes = decode_b64_opaque(ciphertext, "validate.encrypted.ciphertext")?;
        if ct_bytes.len() < AES_GCM_TAG_LEN {
            return Err(CoreError::InvalidKey(
                "Encrypted key ciphertext shorter than AES-GCM tag".to_string(),
            ));
        }
        Ok(())
    }

    /// Expected classical-leg length for a hybrid algorithm.
    ///
    /// L6 fix: dispatch the classical-leg length per algorithm so a future
    /// hybrid using a different classical curve (e.g. `Hybrid…+secp256k1`,
    /// 65-byte uncompressed SEC1 PK) does not have to relax the global
    /// `classical_len != 32` guard and re-open the loose-validation hole
    /// the guard exists to close. Every current hybrid uses a 32-byte
    /// classical leg (X25519 KEM, Ed25519 sig); non-hybrid algorithms are
    /// not legitimate inputs to this dispatch and surface as `None`.
    const fn expected_hybrid_classical_len(algorithm: KeyAlgorithm) -> Option<usize> {
        match algorithm {
            KeyAlgorithm::HybridMlKem512X25519
            | KeyAlgorithm::HybridMlKem768X25519
            | KeyAlgorithm::HybridMlKem1024X25519
            | KeyAlgorithm::HybridMlDsa44Ed25519
            | KeyAlgorithm::HybridMlDsa65Ed25519
            | KeyAlgorithm::HybridMlDsa87Ed25519 => Some(32),
            _ => None,
        }
    }

    /// bound the composite key component lengths against
    /// the expected sizes for the (algorithm, key_type) pair. The
    /// classical leg length is dispatched per algorithm via
    /// [`expected_hybrid_classical_len`](Self::expected_hybrid_classical_len);
    /// the PQ leg has algorithm- and key-type-dependent sizes.
    ///
    /// The classical leg is checked for exact equality. The PQ leg is
    /// checked against a broad range (`PQ_LEN_FLOOR ..= PQ_LEN_CEILING`)
    /// for **both** key types, not against a per-(algorithm, key-type)
    /// exact size:
    ///
    /// - The `Composite` secret-key encoding holds the seed plus the
    ///   embedded public key (the FIPS 203 §6.1 layout for ML-KEM SKs),
    ///   which varies in length across the encoding choices used
    ///   historically, so an exact size is not well-defined here.
    /// - Public-key composites *do* have a fixed size per level, but this
    ///   function does not dispatch on `key_type`, so the same range
    ///   applies. Exact public-key sizes are enforced downstream by the
    ///   primitive constructors (`MlKemPublicKey::new`,
    ///   `HybridKemPublicKey::new`, …), which reject a wrong-length key
    ///   before it can be used. This check is therefore a cheap
    ///   structural pre-filter, not the authoritative length gate.
    fn validate_composite_lengths(
        algorithm: KeyAlgorithm,
        pq_len: usize,
        classical_len: usize,
    ) -> Result<()> {
        let Some(expected_classical) = Self::expected_hybrid_classical_len(algorithm) else {
            return Err(CoreError::InvalidKey(format!(
                "Composite key data is not legitimate for non-hybrid algorithm {algorithm:?}"
            )));
        };
        if classical_len != expected_classical {
            return Err(CoreError::InvalidKey(format!(
                "Hybrid key classical component for {algorithm:?} must be {expected_classical} bytes, got {classical_len}",
            )));
        }
        // Conservative PQ bounds — any future algorithm with larger
        // sizes can extend this without loosening the per-(level,
        // type) check below for current algorithms.
        const PQ_LEN_FLOOR: usize = 32;
        const PQ_LEN_CEILING: usize = 16 * 1024; // SLH-DSA-256 sigs aren't here, but keep headroom
        if !(PQ_LEN_FLOOR..=PQ_LEN_CEILING).contains(&pq_len) {
            return Err(CoreError::InvalidKey(format!(
                "Hybrid key PQ component length {pq_len} outside acceptable range [{PQ_LEN_FLOOR}, {PQ_LEN_CEILING}]",
            )));
        }
        Ok(())
    }
}
