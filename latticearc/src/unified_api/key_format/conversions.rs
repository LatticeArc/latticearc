//! `PortableKey` bridge conversions to/from the concrete typed key types:
//! hybrid KEM, hybrid signature, Ed25519, X25519, ML-KEM, ML-DSA, and
//! symmetric keys.

use super::{KeyAlgorithm, KeyData, KeyType, ML_KEM_PK_METADATA_KEY, PortableKey};
use crate::unified_api::error::{CoreError, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use chrono::Utc;
use std::collections::BTreeMap;

impl PortableKey {
    // --- Bridge: Hybrid KEM keypair ---

    /// Wrap a hybrid KEM keypair (from `generate_hybrid_keypair()`) into
    /// a pair of `PortableKey`s (public + secret).
    ///
    /// Algorithm is auto-derived from the keypair's `security_level`.
    ///
    /// # Errors
    /// Returns an error if secret key export fails.
    pub fn from_hybrid_kem_keypair(
        use_case: crate::types::types::UseCase,
        pk: &crate::hybrid::kem_hybrid::HybridKemPublicKey,
        sk: &crate::hybrid::kem_hybrid::HybridKemSecretKey,
    ) -> Result<(Self, Self)> {
        let algorithm: KeyAlgorithm = pk.security_level().into();

        let pub_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Public,
            key_data: KeyData::from_composite(pk.ml_kem_pk(), pk.ecdh_pk()),
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        };

        let ml_kem_sk = sk
            .ml_kem_sk_bytes()
            .map_err(|e| CoreError::InvalidKey(format!("ML-KEM SK export: {e}")))?;
        let ecdh_seed = sk
            .ecdh_seed_bytes()
            .map_err(|e| CoreError::InvalidKey(format!("ECDH seed export: {e}")))?;

        // Store ML-KEM public key in metadata so the secret key file is
        // self-contained for decryption (no separate public key file needed).
        // This follows the PKCS#12 pattern of bundling public + private material.
        // Note: ECDH public key is not stored — it's derived from the seed at
        // reconstruction time via X25519StaticKeyPair::from_seed_bytes().
        let mut sk_metadata = BTreeMap::new();
        sk_metadata.insert(
            ML_KEM_PK_METADATA_KEY.to_string(),
            serde_json::Value::String(BASE64_ENGINE.encode(pk.ml_kem_pk())),
        );

        let sec_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Secret,
            key_data: KeyData::from_composite(&ml_kem_sk, &*ecdh_seed),
            created: Utc::now(),
            metadata: sk_metadata,
            not_after: None,
        };

        Ok((pub_key, sec_key))
    }

    /// Extract a `HybridPublicKey` from a portable key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a hybrid KEM, the key file is
    /// not marked [`KeyType::Public`], or key data is invalid.
    ///
    /// # M2 fix
    ///
    /// The companion [`to_hybrid_secret_key`](Self::to_hybrid_secret_key)
    /// already required `key_type == Secret`; this extractor previously
    /// accepted any `key_type` and would silently treat the embedded
    /// composite of a [`KeyType::Secret`] file as a public key. Most real
    /// callers were protected by downstream length validation inside
    /// `HybridKemPublicKey::new`, but the asymmetry was a defense-in-depth
    /// hole. The guard makes the contract structural.
    pub fn to_hybrid_public_key(&self) -> Result<crate::hybrid::kem_hybrid::HybridKemPublicKey> {
        // M-B: expiry gate must run before extraction. A key file with
        // `not_after` in the past loads cleanly through validate() (by
        // design — inspection / migration paths need it), but emitting
        // the typed HybridKemPublicKey lets a downstream encrypt path
        // use expired key material. Route through the M-B helper.
        self.validate_with_expiry_now()?;
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "Cannot extract hybrid public key from a non-public key file".to_string(),
            ));
        }

        let level =
            crate::primitives::kem::MlKemSecurityLevel::try_from(self.algorithm).map_err(|()| {
                CoreError::InvalidKey(format!(
                    "Not a hybrid KEM algorithm: {alg:?}",
                    alg = self.algorithm
                ))
            })?;

        let (pq_bytes, classical_bytes) = self.key_data.decode_composite()?;

        Ok(crate::hybrid::kem_hybrid::HybridKemPublicKey::new(pq_bytes, classical_bytes, level))
    }

    /// Reconstruct a `HybridSecretKey` from a portable key pair.
    ///
    /// Requires the corresponding public key PortableKey because ML-KEM
    /// key reconstruction needs both the secret key bytes and public key bytes.
    ///
    /// # Arguments
    /// * `public_key` - The corresponding `PortableKey` with `KeyType::Public`
    ///
    /// # Errors
    /// Returns an error if the algorithm is not hybrid KEM, key data is invalid,
    /// or key reconstruction fails.
    ///
    /// The ML-KEM public key is extracted from the secret key file's metadata
    /// (stored at keygen time), making the secret key file fully self-contained.
    /// No separate public key file is needed for decryption.
    pub fn to_hybrid_secret_key(&self) -> Result<crate::hybrid::kem_hybrid::HybridKemSecretKey> {
        // M-B: see `to_hybrid_public_key`. Expired secret keys must not be
        // turned into a typed secret-key value that a downstream decrypt
        // / agree path would use.
        self.validate_with_expiry_now()?;
        let level =
            crate::primitives::kem::MlKemSecurityLevel::try_from(self.algorithm).map_err(|()| {
                CoreError::InvalidKey(format!(
                    "Not a hybrid KEM algorithm: {alg:?}",
                    alg = self.algorithm
                ))
            })?;

        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "Cannot reconstruct secret key from a public key".to_string(),
            ));
        }

        // Use the zeroizing decoder so the ML-KEM secret-key bytes and
        // the X25519 seed are wiped from heap memory when this scope
        // ends, regardless of which downstream branch we take.
        let (ml_kem_sk, ecdh_seed_vec) = self.key_data.decode_composite_zeroized()?;

        // derive the ML-KEM public key from the SK
        // bytes' embedded layout (FIPS 203 §6.1) rather than trusting
        // the unauthenticated `ml_kem_pk` metadata field. The PK
        // metadata, when present, was used as load-time input to
        // HKDF info — but the metadata BTreeMap is only included in
        // AAD when the SK file is passphrase-encrypted (see test at
        // line 2980). Plaintext-stored SKs had no integrity binding
        // for that field, so a file-write attacker could swap it.
        // Pattern-6: plaintext-keyfile path is reachable without AEAD,
        // so the upstream `MlKemSecretKey::new` / `embedded_public_key_bytes`
        // errors are attacker-touchable. Collapse to a fixed string and
        // route the raw error to tracing::debug! for operator visibility.
        let parsed_sk =
            crate::primitives::kem::ml_kem::MlKemSecretKey::new(level, ml_kem_sk.to_vec())
                .map_err(|e| {
                    tracing::debug!(error = %e, "plaintext keyfile: ML-KEM SK parse rejected");
                    CoreError::InvalidKey("Invalid ML-KEM secret key".to_string())
                })?;
        let ml_kem_pk_slice = parsed_sk.embedded_public_key_bytes().map_err(|e| {
            tracing::debug!(error = %e, "plaintext keyfile: ML-KEM SK pk-extract rejected");
            CoreError::InvalidKey("Invalid ML-KEM secret key".to_string())
        })?;
        let ml_kem_pk: Vec<u8> = ml_kem_pk_slice.to_vec();

        if ecdh_seed_vec.len() != 32 {
            return Err(CoreError::InvalidKey(format!(
                "X25519 seed must be 32 bytes, got {}",
                ecdh_seed_vec.len()
            )));
        }

        let mut ecdh_seed = zeroize::Zeroizing::new([0u8; 32]);
        ecdh_seed.copy_from_slice(&ecdh_seed_vec);

        crate::hybrid::kem_hybrid::HybridKemSecretKey::from_serialized(
            level, &ml_kem_sk, &ml_kem_pk, &ecdh_seed,
        )
        .map_err(|e| {
            tracing::debug!(error = %e, "plaintext keyfile: hybrid SK reconstruction rejected");
            CoreError::InvalidKey("Hybrid secret key reconstruction failed".to_string())
        })
    }

    // --- Bridge: Hybrid signature keypair ---

    /// Wrap a hybrid signature keypair (from `generate_hybrid_signing_keypair()`)
    /// into a pair of `PortableKey`s (public + secret).
    ///
    /// The ML-DSA parameter set is auto-detected from the public key byte length:
    /// - 1,312 bytes → ML-DSA-44 (`HybridMlDsa44Ed25519`)
    /// - 1,952 bytes → ML-DSA-65 (`HybridMlDsa65Ed25519`)
    /// - 2,592 bytes → ML-DSA-87 (`HybridMlDsa87Ed25519`)
    ///
    /// # Arguments
    /// * `use_case` - The use case this key was generated for
    /// * `pk` - Hybrid signature public key (ML-DSA + Ed25519)
    /// * `sk` - Hybrid signature secret key (ML-DSA + Ed25519)
    ///
    /// # Errors
    /// Returns an error if `pk.parameter_set()` does not map to a known
    /// hybrid-signature `KeyAlgorithm` variant. (As of 0.8.0 all three
    /// ML-DSA parameter sets are mapped, so this is currently
    /// unreachable; the `Result` shape is retained for forward
    /// compatibility with future ML-DSA variants.)
    pub fn from_hybrid_sig_keypair(
        use_case: crate::types::types::UseCase,
        pk: &crate::hybrid::sig_hybrid::HybridSigPublicKey,
        sk: &crate::hybrid::sig_hybrid::HybridSigSecretKey,
    ) -> Result<(Self, Self)> {
        // Read the parameter set off the typed handle introduced in
        // 0.8.0 — see HybridSigPublicKey::parameter_set. Earlier
        // revisions sniffed it from the PK byte length (1312/1952/2592);
        // that worked because the FIPS 204 sets have unique lengths,
        // but it was inconsistent with the KEM side (which used the
        // typed level()) and would silently break if any future ML-DSA
        // variant collided on length.
        let algorithm: KeyAlgorithm = pk.parameter_set().into();

        let pub_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Public,
            key_data: KeyData::from_composite(pk.ml_dsa_pk(), pk.ed25519_pk()),
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        };

        let sec_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Secret,
            key_data: KeyData::from_composite(
                sk.expose_ml_dsa_secret(),
                sk.expose_ed25519_secret(),
            ),
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        };

        Ok((pub_key, sec_key))
    }

    /// Extract a hybrid signature `HybridPublicKey` from a portable key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a hybrid signature, the key
    /// file is not marked [`KeyType::Public`], or key data is invalid.
    ///
    /// # M2 fix
    ///
    /// Mirrors [`to_hybrid_public_key`](Self::to_hybrid_public_key). See its
    /// docs for the asymmetry rationale.
    pub fn to_hybrid_sig_public_key(
        &self,
    ) -> Result<crate::hybrid::sig_hybrid::HybridSigPublicKey> {
        // M-B: see `to_hybrid_public_key`.
        self.validate_with_expiry_now()?;
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "Cannot extract hybrid signature public key from a non-public key file".to_string(),
            ));
        }

        let parameter_set = crate::primitives::sig::ml_dsa::MlDsaParameterSet::try_from(
            self.algorithm,
        )
        .map_err(|()| {
            CoreError::InvalidKey(format!(
                "Not a hybrid signature algorithm: {alg:?}",
                alg = self.algorithm
            ))
        })?;

        let (pq_bytes, classical_bytes) = self.key_data.decode_composite()?;

        crate::hybrid::sig_hybrid::HybridSigPublicKey::new(parameter_set, pq_bytes, classical_bytes)
            .map_err(|e| CoreError::InvalidKey(format!("hybrid sig public key: {e}")))
    }

    /// Extract a hybrid signature `HybridSecretKey` from a portable key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not hybrid signature or key data is invalid.
    pub fn to_hybrid_sig_secret_key(
        &self,
    ) -> Result<crate::hybrid::sig_hybrid::HybridSigSecretKey> {
        // M-B: see `to_hybrid_public_key`.
        self.validate_with_expiry_now()?;
        let parameter_set = crate::primitives::sig::ml_dsa::MlDsaParameterSet::try_from(
            self.algorithm,
        )
        .map_err(|()| {
            CoreError::InvalidKey(format!(
                "Not a hybrid signature algorithm: {alg:?}",
                alg = self.algorithm
            ))
        })?;

        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "Cannot reconstruct secret key from a public key".to_string(),
            ));
        }

        // Use the zeroizing decoder so the ML-DSA secret-key bytes and
        // Ed25519 seed are never held as bare `Vec<u8>` between decode
        // and `Zeroizing` wrapping.
        let (pq_bytes, classical_bytes) = self.key_data.decode_composite_zeroized()?;

        Ok(crate::hybrid::sig_hybrid::HybridSigSecretKey::new(
            parameter_set,
            pq_bytes,
            classical_bytes,
        ))
    }

    // --- Bridge: Simple keypair (Ed25519, ML-KEM, ML-DSA, etc.) ---

    /// Wrap a simple keypair (public + private byte arrays) into a pair of `PortableKey`s.
    ///
    /// For non-hybrid algorithms that produce `(PublicKey, PrivateKey)`.
    #[must_use]
    pub fn from_keypair(
        use_case: crate::types::types::UseCase,
        algorithm: KeyAlgorithm,
        public_key: &[u8],
        private_key: &[u8],
    ) -> (Self, Self) {
        let pub_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Public,
            key_data: KeyData::from_raw(public_key),
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        };

        let sec_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Secret,
            key_data: KeyData::from_raw(private_key),
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        };

        (pub_key, sec_key)
    }

    // --- Bridge: Ed25519 keypair ---

    /// Wrap an Ed25519 keypair into a pair of `PortableKey`s (public + secret).
    ///
    /// Convenience wrapper around [`from_keypair`](Self::from_keypair) that
    /// sets the algorithm to `Ed25519`.
    #[must_use]
    pub fn from_ed25519_keypair(
        use_case: crate::types::types::UseCase,
        verifying_key: &[u8],
        signing_key: &[u8],
    ) -> (Self, Self) {
        Self::from_keypair(use_case, KeyAlgorithm::Ed25519, verifying_key, signing_key)
    }

    /// Extract Ed25519 verifying key bytes (32 bytes).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not Ed25519 or key type is not Public.
    pub fn to_ed25519_verifying_key_bytes(&self) -> Result<Vec<u8>> {
        if self.algorithm != KeyAlgorithm::Ed25519 {
            return Err(CoreError::InvalidKey(format!("Not an Ed25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "Ed25519 verifying key requires Public key type".to_string(),
            ));
        }
        self.key_data.decode_raw()
    }

    /// Extract Ed25519 signing key bytes (zeroized on drop).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not Ed25519 or key type is not Secret.
    pub fn to_ed25519_signing_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.algorithm != KeyAlgorithm::Ed25519 {
            return Err(CoreError::InvalidKey(format!("Not an Ed25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "Ed25519 signing key requires Secret key type".to_string(),
            ));
        }
        self.key_data.decode_raw_zeroized()
    }

    // --- Bridge: X25519 keypair ---

    /// Wrap an X25519 keypair into a pair of `PortableKey`s (public + secret).
    ///
    /// The secret key is stored as the 32-byte seed
    /// (from [`X25519StaticKeyPair::seed_bytes()`](crate::primitives::kem::ecdh::X25519StaticKeyPair::seed_bytes)).
    #[must_use]
    pub fn from_x25519_keypair(
        use_case: crate::types::types::UseCase,
        public_key: &[u8; 32],
        seed: &[u8; 32],
    ) -> (Self, Self) {
        Self::from_keypair(use_case, KeyAlgorithm::X25519, public_key, seed)
    }

    /// Extract X25519 public key bytes (32 bytes).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not X25519 or key type is not Public.
    pub fn to_x25519_public_key_bytes(&self) -> Result<Vec<u8>> {
        if self.algorithm != KeyAlgorithm::X25519 {
            return Err(CoreError::InvalidKey(format!("Not an X25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "X25519 public key requires Public key type".to_string(),
            ));
        }
        self.key_data.decode_raw()
    }

    /// Extract X25519 secret key seed bytes (32 bytes, zeroized on drop).
    ///
    /// Use with [`X25519StaticKeyPair::from_seed_bytes()`](crate::primitives::kem::ecdh::X25519StaticKeyPair::from_seed_bytes)
    /// to reconstruct the key pair for agreement operations.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not X25519 or key type is not Secret.
    pub fn to_x25519_secret_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.algorithm != KeyAlgorithm::X25519 {
            return Err(CoreError::InvalidKey(format!("Not an X25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "X25519 secret key requires Secret key type".to_string(),
            ));
        }
        self.key_data.decode_raw_zeroized()
    }

    // --- Bridge: ML-KEM keypair ---

    /// Wrap an ML-KEM keypair into a pair of `PortableKey`s (public + secret).
    ///
    /// Algorithm is auto-detected from the public key's security level.
    #[must_use]
    pub fn from_ml_kem_keypair(
        use_case: crate::types::types::UseCase,
        pk: &crate::primitives::kem::ml_kem::MlKemPublicKey,
        sk: &crate::primitives::kem::ml_kem::MlKemSecretKey,
    ) -> (Self, Self) {
        let algorithm = match pk.security_level() {
            crate::primitives::kem::MlKemSecurityLevel::MlKem512 => KeyAlgorithm::MlKem512,
            crate::primitives::kem::MlKemSecurityLevel::MlKem768 => KeyAlgorithm::MlKem768,
            crate::primitives::kem::MlKemSecurityLevel::MlKem1024 => KeyAlgorithm::MlKem1024,
        };
        Self::from_keypair(use_case, algorithm, pk.as_bytes(), sk.expose_secret())
    }

    /// Extract ML-KEM public (encapsulation) key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-KEM variant,
    /// key type is not Public, or the key data is malformed.
    pub fn to_ml_kem_public_key(&self) -> Result<crate::primitives::kem::ml_kem::MlKemPublicKey> {
        let level = match self.algorithm {
            KeyAlgorithm::MlKem512 => crate::primitives::kem::MlKemSecurityLevel::MlKem512,
            KeyAlgorithm::MlKem768 => crate::primitives::kem::MlKemSecurityLevel::MlKem768,
            KeyAlgorithm::MlKem1024 => crate::primitives::kem::MlKemSecurityLevel::MlKem1024,
            other => {
                return Err(CoreError::InvalidKey(format!(
                    "Not a standalone ML-KEM algorithm: {other:?}"
                )));
            }
        };
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "ML-KEM public key requires Public key type".to_string(),
            ));
        }
        let bytes = self.key_data.decode_raw()?;
        crate::primitives::kem::ml_kem::MlKemPublicKey::new(level, bytes)
            .map_err(|e| CoreError::InvalidKey(format!("ML-KEM public key: {e}")))
    }

    /// Extract ML-KEM secret (decapsulation) key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-KEM variant,
    /// key type is not Secret, or the key data is malformed.
    pub fn to_ml_kem_secret_key(&self) -> Result<crate::primitives::kem::ml_kem::MlKemSecretKey> {
        let level = match self.algorithm {
            KeyAlgorithm::MlKem512 => crate::primitives::kem::MlKemSecurityLevel::MlKem512,
            KeyAlgorithm::MlKem768 => crate::primitives::kem::MlKemSecurityLevel::MlKem768,
            KeyAlgorithm::MlKem1024 => crate::primitives::kem::MlKemSecurityLevel::MlKem1024,
            other => {
                return Err(CoreError::InvalidKey(format!(
                    "Not a standalone ML-KEM algorithm: {other:?}"
                )));
            }
        };
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "ML-KEM secret key requires Secret key type".to_string(),
            ));
        }
        // Use the zeroizing decoder so the ML-KEM secret-key bytes are
        // wiped from heap memory when this scope exits, even on the
        // error path where `MlKemSecretKey::new` rejects malformed
        // material before consuming the bytes.
        let bytes = self.key_data.decode_raw_zeroized()?;
        crate::primitives::kem::ml_kem::MlKemSecretKey::new(level, bytes.to_vec())
            .map_err(|e| CoreError::InvalidKey(format!("ML-KEM secret key: {e}")))
    }

    // --- Bridge: ML-DSA keypair ---

    /// Extract ML-DSA verifying (public) key bytes.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-DSA variant
    /// or key type is not Public.
    pub fn to_ml_dsa_verifying_key_bytes(&self) -> Result<Vec<u8>> {
        if !matches!(
            self.algorithm,
            KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87
        ) {
            return Err(CoreError::InvalidKey(format!(
                "Not a standalone ML-DSA algorithm: {:?}",
                self.algorithm
            )));
        }
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "ML-DSA verifying key requires Public key type".to_string(),
            ));
        }
        self.key_data.decode_raw()
    }

    /// Extract ML-DSA signing (secret) key bytes (zeroized on drop).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-DSA variant
    /// or key type is not Secret.
    pub fn to_ml_dsa_signing_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if !matches!(
            self.algorithm,
            KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87
        ) {
            return Err(CoreError::InvalidKey(format!(
                "Not a standalone ML-DSA algorithm: {:?}",
                self.algorithm
            )));
        }
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "ML-DSA signing key requires Secret key type".to_string(),
            ));
        }
        self.key_data.decode_raw_zeroized()
    }

    // --- Bridge: Symmetric key ---

    /// Create a `PortableKey` from raw symmetric key bytes.
    ///
    /// now requires `security_level: SecurityLevel`. The
    /// previous signature produced a `PortableKey` with both
    /// `use_case = None` AND `security_level = None`, which the
    /// invariant check at deserialization (`from_json` / `from_cbor`)
    /// rejects. Symmetric keys round-tripped through JSON/CBOR were
    /// silently broken on reload. The added parameter makes the
    /// invariant satisfiable at construction time and is the same
    /// shape callers already use for non-symmetric constructors.
    /// **Breaking change**: callers must add a `security_level`
    /// argument.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not symmetric (AES-256 or ChaCha20).
    pub fn from_symmetric_key(
        algorithm: KeyAlgorithm,
        security_level: crate::types::SecurityLevel,
        key: &[u8],
    ) -> Result<Self> {
        if !algorithm.is_symmetric() {
            return Err(CoreError::InvalidKey(format!(
                "{algorithm:?} is not a symmetric algorithm"
            )));
        }
        Ok(Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: Some(security_level),
            algorithm,
            key_type: KeyType::Symmetric,
            key_data: KeyData::from_raw(key),
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        })
    }
}
