//! `PortableKey` passphrase-based encryption (LPK v1 encrypted variant):
//! `encrypt_with_passphrase`, `decrypt_with_passphrase`, and the
//! AEAD-AAD byte-layout builder they share.

use super::{
    AES_256_KEY_LEN, AES_GCM_AEAD_ID, AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN,
    ENCRYPTED_ENVELOPE_VERSION, KeyAlgorithm, KeyData, KeyType, PBKDF2_DEFAULT_ITERATIONS,
    PBKDF2_KDF_ID, PBKDF2_MIN_ITERATIONS, PBKDF2_SALT_LEN, PortableKey,
};
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::serialization::{decode_b64_opaque, decode_json_opaque};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use std::collections::BTreeMap;

impl PortableKey {
    // --- Passphrase-based encryption (LPK v1 encrypted variant) ---

    /// Returns `true` if the key material is passphrase-encrypted.
    ///
    /// Encrypted keys must be unwrapped via [`Self::decrypt_with_passphrase`]
    /// before their raw bytes can be extracted via [`KeyData::decode_raw`] or
    /// [`KeyData::decode_composite`].
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(self.key_data, KeyData::Encrypted { .. })
    }

    /// Encrypt the key material in place using a passphrase.
    ///
    /// Derives a 32-byte AES key via PBKDF2-HMAC-SHA256 (600,000 iterations,
    /// 16-byte random salt) and encrypts the JSON-serialized `KeyData` under
    /// AES-256-GCM with a fresh 12-byte random nonce. The full envelope
    /// (version, algorithm, key_type, KDF name, iteration count, salt, AEAD
    /// name) is mixed into the AEAD AAD, so tampering with any metadata
    /// field on disk causes decryption to fail at the tag check. See
    /// [`Self::encryption_aad`] for the exact byte layout.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is already encrypted, if the passphrase is
    /// empty, or if the KDF / AEAD operation fails.
    pub fn encrypt_with_passphrase(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.is_encrypted() {
            return Err(CoreError::InvalidKey("Key is already passphrase-encrypted".to_string()));
        }
        if passphrase.is_empty() {
            return Err(CoreError::InvalidKey("Passphrase must not be empty".to_string()));
        }

        // 1. Serialize the current plaintext KeyData to its own JSON. We
        //    serialize only the KeyData (not the whole PortableKey) so the
        //    ciphertext is self-contained and round-trips cleanly.
        let plaintext_json = serde_json::to_vec(&self.key_data).map_err(|e| {
            CoreError::SerializationError(format!(
                "Failed to serialize key data for encryption: {e}"
            ))
        })?;
        let plaintext = zeroize::Zeroizing::new(plaintext_json);

        // 2. Generate a fresh random salt.
        let salt = crate::primitives::rand::csprng::random_bytes(PBKDF2_SALT_LEN);

        // 3. Derive the AES key via PBKDF2-HMAC-SHA256. Salt-length
        // validation lives at the `pbkdf2(...)` call below; `with_salt`
        // is intentionally infallible so wire-format parsers can also
        // round-trip pre-0.8.0 short-salt envelopes for inspection.
        let kdf_params = crate::primitives::kdf::pbkdf2::Pbkdf2Params::with_salt(&salt)
            .iterations(PBKDF2_DEFAULT_ITERATIONS)
            .key_length(AES_256_KEY_LEN);
        let derived = crate::primitives::kdf::pbkdf2::pbkdf2(passphrase, &kdf_params)
            .map_err(|e| CoreError::InvalidKey(format!("PBKDF2 derivation failed: {e}")))?;

        // 4. Encrypt via AES-256-GCM with a fresh random nonce. Bind the
        //    full envelope (version, algorithm, key_type, KDF name,
        //    iterations, salt, AEAD name) to the ciphertext via AAD so an
        //    attacker who modifies any of these fields on disk breaks the
        //    AEAD tag.
        use crate::primitives::aead::AeadCipher;
        let cipher = crate::primitives::aead::aes_gcm::AesGcm256::new(derived.expose_secret())
            .map_err(|e| CoreError::InvalidKey(format!("Failed to initialize AES-256-GCM: {e}")))?;
        let aad = Self::encryption_aad(
            ENCRYPTED_ENVELOPE_VERSION,
            self.algorithm,
            self.key_type,
            PBKDF2_KDF_ID,
            PBKDF2_DEFAULT_ITERATIONS,
            &salt,
            AES_GCM_AEAD_ID,
            &self.metadata,
        )?;
        let (nonce, mut ct, tag) = cipher
            .seal(&plaintext, Some(&aad))
            .map_err(|e| CoreError::InvalidKey(format!("AES-256-GCM sealing failed: {e}")))?;

        // 5. Pack ciphertext || tag for on-wire storage.
        ct.extend_from_slice(&tag);

        // 6. Replace the plaintext KeyData with the encrypted envelope.
        self.key_data = KeyData::Encrypted {
            enc: ENCRYPTED_ENVELOPE_VERSION,
            kdf: PBKDF2_KDF_ID.to_string(),
            kdf_iterations: PBKDF2_DEFAULT_ITERATIONS,
            kdf_salt: BASE64_ENGINE.encode(&salt),
            aead: AES_GCM_AEAD_ID.to_string(),
            nonce: BASE64_ENGINE.encode(nonce),
            ciphertext: BASE64_ENGINE.encode(&ct),
        };

        Ok(())
    }

    /// Decrypt the key material in place using a passphrase.
    ///
    /// Reverses [`Self::encrypt_with_passphrase`]. On success the `key_data`
    /// field is replaced with the underlying `Single` or `Composite` variant.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not encrypted, the envelope is
    /// malformed, the passphrase is wrong (AEAD authentication fails), or
    /// the decrypted plaintext is not a valid `KeyData` serialization.
    pub fn decrypt_with_passphrase(&mut self, passphrase: &[u8]) -> Result<()> {
        if passphrase.is_empty() {
            return Err(CoreError::InvalidKey("Passphrase must not be empty".to_string()));
        }

        // Borrow the envelope to validate shape and decode its fields into
        // owned bytes. After validation the `kdf` and `aead` string fields
        // are known to equal the envelope's fixed constants, so we don't
        // bother cloning them into `Decoded` — we pass the constants to
        // `encryption_aad` at the call site instead.
        struct Decoded {
            enc: u32,
            kdf_iterations: u32,
            salt: Vec<u8>,
            nonce: [u8; AES_GCM_NONCE_LEN],
            ct_and_tag: Vec<u8>,
        }
        let decoded = match &self.key_data {
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
                let salt = decode_b64_opaque(kdf_salt, "decrypt.encrypted.kdf_salt")?;
                let nonce_bytes = decode_b64_opaque(nonce, "decrypt.encrypted.nonce")?;
                let mut nonce_array = [0u8; AES_GCM_NONCE_LEN];
                nonce_array.copy_from_slice(&nonce_bytes);
                let ct_and_tag = decode_b64_opaque(ciphertext, "decrypt.encrypted.ciphertext")?;
                Decoded {
                    enc: *enc,
                    kdf_iterations: *kdf_iterations,
                    salt,
                    nonce: nonce_array,
                    ct_and_tag,
                }
            }
            _ => {
                return Err(CoreError::InvalidKey("Key is not passphrase-encrypted".to_string()));
            }
        };
        let Decoded { enc, kdf_iterations, salt, nonce: nonce_array, ct_and_tag } = decoded;

        let tag_offset = ct_and_tag
            .len()
            .checked_sub(AES_GCM_TAG_LEN)
            .ok_or_else(|| CoreError::InvalidKey("Ciphertext shorter than tag".to_string()))?;
        let (ct_bytes, tag_bytes) = ct_and_tag.split_at(tag_offset);
        let mut tag_array = [0u8; AES_GCM_TAG_LEN];
        tag_array.copy_from_slice(tag_bytes);

        // Derive the AES key from the passphrase + salt.
        // `with_salt` is the right tool here: `salt` was
        // deserialized from an externally-supplied envelope and may be
        // a pre-0.8.0 short salt that `with_salt`'s NIST SP 800-132 §5.1
        // floor would reject. The validating min-length check happens at
        // the `pbkdf2(...)` call below instead, so the unchecked
        // construction cannot smuggle a short salt past actual
        // derivation. This is the documented wire-format-parser use
        // case for `with_salt`.
        let kdf_params = crate::primitives::kdf::pbkdf2::Pbkdf2Params::with_salt(&salt)
            .iterations(kdf_iterations)
            .key_length(AES_256_KEY_LEN);
        // Use the legacy load-side floor (PBKDF2_MIN_ITERATIONS = 100k)
        // rather than the public OWASP 2023 floor: the iteration count
        // here is integrity-protected by the envelope AAD, so a count
        // below 600k means the legitimate keyholder wrote it under
        // OWASP 2018 guidance. Refusing to load it would strand
        // historical keys; the caller already saw a re-protect warning
        // in `validate_encrypted_envelope_fields` above.
        let derived = crate::primitives::kdf::pbkdf2::pbkdf2_with_floor(
            passphrase,
            &kdf_params,
            PBKDF2_MIN_ITERATIONS,
        )
        .map_err(|e| CoreError::InvalidKey(format!("PBKDF2 derivation failed: {e}")))?;

        // Decrypt. A wrong passphrase produces a wrong AES key, which causes
        // AEAD authentication to fail with an opaque error — we do NOT leak
        // whether the passphrase was wrong vs. the envelope was corrupted.
        // The AAD binds the full envelope so any tampered metadata field
        // also breaks the tag.
        use crate::primitives::aead::AeadCipher;
        let cipher = crate::primitives::aead::aes_gcm::AesGcm256::new(derived.expose_secret())
            .map_err(|e| CoreError::InvalidKey(format!("Failed to initialize AES-256-GCM: {e}")))?;
        // `kdf` and `aead` are the constants: `validate_encrypted_envelope_fields`
        // rejected any other value, so we can pass the literals directly
        // instead of cloning them out of the borrowed envelope.
        let aad = Self::encryption_aad(
            enc,
            self.algorithm,
            self.key_type,
            PBKDF2_KDF_ID,
            kdf_iterations,
            &salt,
            AES_GCM_AEAD_ID,
            &self.metadata,
        )?;
        let plaintext = cipher
            .decrypt(&nonce_array, ct_bytes, &tag_array, Some(&aad))
            .map_err(|_e| {
                CoreError::InvalidKey(
                    "Passphrase-protected key unwrap failed (wrong passphrase or corrupted envelope)"
                        .to_string(),
                )
            })?;

        // Deserialize the plaintext bytes back into a KeyData variant.
        // Defense-in-depth: AEAD authentication has already passed by
        // this point, so an attacker cannot reach this branch without
        // the passphrase — but a corrupted between-sessions disk write
        // could surface attacker-controlled token detail through
        // serde_json's error display. Route through the opaque helper.
        let plaintext_str = std::str::from_utf8(&plaintext).map_err(|e| {
            tracing::debug!(error = %e, "decrypted keyfile: non-UTF8 plaintext");
            CoreError::SerializationError("decrypted plaintext is not UTF-8".to_string())
        })?;
        let new_key_data: KeyData = decode_json_opaque(plaintext_str, "decrypt.plaintext")?;
        // Reject nested encryption (prevents re-wrap confusion).
        if matches!(new_key_data, KeyData::Encrypted { .. }) {
            return Err(CoreError::InvalidKey(
                "Decrypted payload was itself an encrypted envelope".to_string(),
            ));
        }

        // Stage the new KeyData and run the same coherence check that
        // `from_json`/`load_from_file` apply on entry. An attacker who
        // crafted an envelope where the AEAD-bound metadata declares one
        // algorithm but the decrypted KeyData payload describes another
        // would otherwise install a structurally-incoherent PortableKey
        // that the rest of the API would only catch much later (or, in
        // some paths, not at all). Run validation before mutating self
        // so a failed decrypt leaves the receiver untouched.
        let original = std::mem::replace(&mut self.key_data, new_key_data);
        if let Err(e) = self.validate() {
            // Restore the original encrypted envelope on validation
            // failure so the caller can retry, inspect, or re-wrap.
            self.key_data = original;
            return Err(e);
        }
        Ok(())
    }

    /// Build the AAD bound to an encrypted key envelope.
    ///
    /// AEAD AAD is authenticated (not encrypted), so fields folded in here
    /// are protected against tampering but not against disclosure. Binding
    /// all envelope parameters — version, algorithm, key type, KDF name,
    /// iteration count, salt, and AEAD name — ensures that any attacker
    /// modification of a stored key file's metadata or KDF parameters
    /// causes `cipher.decrypt` to fail with an opaque error.
    ///
    /// Uses stable kebab-case / lowercase names (`ml-kem-768`, `secret`)
    /// via `canonical_name` accessors on the enums. These are load-bearing:
    /// changing the returned strings breaks every existing encrypted key
    /// file. A pinned byte-level test in the `tests` module guards this.
    ///
    /// # Byte layout
    ///
    /// ```text
    /// "latticearc-lpk-v1-enc" || 0x00
    /// || enc (u32 BE)
    /// || algorithm_name || 0x00
    /// || key_type_name || 0x00
    /// || kdf_name || 0x00
    /// || kdf_iterations (u32 BE)
    /// || kdf_salt_len (u32 BE) || kdf_salt_raw_bytes
    /// || aead_name
    /// ```
    ///
    /// Length prefixes and null separators prevent ambiguity between
    /// adjacent variable-length fields. The salt is included as its raw
    /// (base64-decoded) bytes, not the base64 string, so an attacker
    /// cannot use base64 non-canonical encodings to get past the check.
    ///
    /// `pub(super)`: exercised directly by `key_format::tests_a`'s
    /// AAD byte-layout-stability regression tests.
    #[expect(
        clippy::too_many_arguments,
        reason = "8 fields are inherent to the AAD layout; bundling into a struct adds indirection without simplifying the call sites."
    )]
    pub(super) fn encryption_aad(
        enc: u32,
        algorithm: KeyAlgorithm,
        key_type: KeyType,
        kdf: &str,
        kdf_iterations: u32,
        kdf_salt: &[u8],
        aead: &str,
        metadata: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let algorithm_name = algorithm.canonical_name();
        let key_type_name = key_type.canonical_name();

        // Canonical metadata serialization: BTreeMap iterates in
        // lexicographic key order, so `serde_json::to_vec` produces
        // deterministic bytes for flat string→string maps (the actual
        // shape used by this format — `ml_kem_pk` and friends are
        // base64 strings). Length-prefix the result so a metadata
        // append/truncate cannot collide with an adjacent AAD field.
        let metadata_bytes = serde_json::to_vec(metadata).map_err(|e| {
            CoreError::SerializationError(format!(
                "Failed to canonicalize key-format metadata for AEAD AAD: {e}"
            ))
        })?;
        let metadata_len_u32 = u32::try_from(metadata_bytes.len()).map_err(|_e| {
            CoreError::SerializationError(
                "Encrypted-envelope metadata exceeds u32::MAX bytes".to_string(),
            )
        })?;

        let mut aad = Vec::with_capacity(
            b"latticearc-lpk-v3-enc"
                .len()
                .saturating_add(1) // null after magic
                .saturating_add(4) // enc
                .saturating_add(algorithm_name.len())
                .saturating_add(1) // null after algorithm_name
                .saturating_add(key_type_name.len())
                .saturating_add(1) // null after key_type_name
                .saturating_add(kdf.len())
                .saturating_add(1) // null after kdf
                .saturating_add(4) // kdf_iterations
                .saturating_add(4) // salt len
                .saturating_add(kdf_salt.len())
                .saturating_add(aead.len())
                .saturating_add(1) // null after aead (parallel to other string fields)
                .saturating_add(4) // metadata len
                .saturating_add(metadata_bytes.len()),
        );
        // AAD magic `lpk-v3-enc`: bumped from `lpk-v2-enc` for the
        // canonicalization fix below. The previous v2 layout omitted the
        // null terminator after the `aead` string field while every other
        // string field (label, algorithm_name, key_type_name, kdf) had
        // one — the moment a second AEAD name was added (e.g.
        // ChaCha20-Poly1305), the (aead || metadata_len) concatenation
        // could collide with a different (aead' || metadata_len')
        // prefix-shifted by the length difference. Adding the terminator
        // closes the collision class. The envelope's `enc` wire field is
        // bumped to `ENCRYPTED_ENVELOPE_VERSION` (3) in lockstep, so a v2
        // envelope is caught by the version check at load time and
        // reported with a distinct "re-protect" error rather than failing
        // opaquely as a wrong passphrase.
        aad.extend_from_slice(b"latticearc-lpk-v3-enc");
        aad.push(0);
        aad.extend_from_slice(&enc.to_be_bytes());
        aad.extend_from_slice(algorithm_name.as_bytes());
        aad.push(0);
        aad.extend_from_slice(key_type_name.as_bytes());
        aad.push(0);
        aad.extend_from_slice(kdf.as_bytes());
        aad.push(0);
        aad.extend_from_slice(&kdf_iterations.to_be_bytes());
        // The `unwrap_or(u32::MAX)` saturation that would have lived
        // here was collapsed at four other length-prefix sites for
        // good reason: saturation collapses every `>4 GiB` salt onto
        // the same length prefix, leading to an AAD canonicalization
        // collision. Refuse instead, with the same shape as the
        // metadata-len overflow check above.
        let salt_len_u32 = u32::try_from(kdf_salt.len()).map_err(|_e| {
            CoreError::SerializationError(
                "Encrypted-envelope kdf_salt exceeds u32::MAX bytes".to_string(),
            )
        })?;
        aad.extend_from_slice(&salt_len_u32.to_be_bytes());
        aad.extend_from_slice(kdf_salt);
        aad.extend_from_slice(aead.as_bytes());
        // null terminator after `aead` to match every
        // other string field. Without it, a hypothetical
        // (aead="ChaCha20Poly1305", metadata_len=N) pair could
        // canonicalize identically to (aead="ChaCha20", metadata_len=
        // 'P'<<24|...) for cleverly-crafted suffixes. Today aead is
        // hard-coded to AES-256-GCM so unexploitable; the fix closes
        // the collision class before a second AEAD ships.
        aad.push(0);
        aad.extend_from_slice(&metadata_len_u32.to_be_bytes());
        aad.extend_from_slice(&metadata_bytes);
        Ok(aad)
    }
}
