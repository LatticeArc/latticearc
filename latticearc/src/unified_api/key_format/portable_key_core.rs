//! `PortableKey` core: struct definition, redacted `Debug`, constant-time
//! equality, the use-case/security-level → algorithm resolvers, and the
//! constructor / accessor / metadata inherent methods.
//!
//! The remaining `PortableKey` inherent methods live in sibling modules
//! (`conversions`, `validation`, `encryption`, `serialization`) as
//! additional `impl PortableKey` blocks — this is the single owning
//! module for the type's fields and their `pub(super)` visibility.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{KeyAlgorithm, KeyData, KeyType};
use crate::unified_api::error::{CoreError, Result};
use chrono::{DateTime, Utc};

// ============================================================================
// PortableKey
// ============================================================================

/// Portable, versioned key container for all LatticeArc key types.
///
/// Keys are identified by **use case** or **security level** — mirroring how
/// the library's API works. The specific algorithm is auto-derived from these
/// and stored internally for version-stability (the mapping may change between
/// library releases). Users never specify algorithms directly.
///
/// At least one of `use_case` or `security_level` must be present. If both
/// are set, `security_level` takes precedence for algorithm resolution
/// (matching `CryptoConfig` behavior).
///
/// # Dual-Format Serialization
///
/// - **JSON** — human-readable: CLI, REST APIs, debugging
/// - **CBOR** (RFC 8949) — compact binary: wire protocol, database, containers
///
/// # Enterprise Extensions
///
/// The `metadata` map is the extension point for enterprise features.
/// Enterprise crates store additional fields (expiry, hardware binding,
/// dimensions, etc.) as metadata entries and provide typed accessor traits.
/// The base library preserves all metadata during roundtrips.
///
/// # Security Note: Clone
///
/// `PortableKey` derives `Clone` because it is a **serialization type** — it
/// is designed to be written to disk, sent over the wire, or stored in a
/// database. Cloning is required for serialization roundtrip testing and for
/// passing keys through API boundaries.
///
/// **Do not use `PortableKey` as a long-lived runtime key holder.** Extract
/// the concrete key type (e.g., `HybridPublicKey`, `HybridSecretKey`) via the
/// `to_hybrid_*` bridge methods, and work with those instead. Secret key
/// material inside `KeyData` is zeroized on drop via the explicit `Drop` impl.
///
/// # Constant-Time Comparison
///
/// `PortableKey` implements [`subtle::ConstantTimeEq`]. Metadata fields
/// (`version`, `algorithm`, `key_type`, `use_case`, `security_level`, `created`,
/// `metadata`) are compared with non-CT equality because they are serialized
/// in plaintext on the wire — their equality is not a secret. The `key_data`
/// field (containing actual key material, including encrypted envelopes) is
/// compared in constant time via the canonical `subtle::ConstantTimeEq` pattern.
///
/// Cross-variant comparisons (`Single` vs `Composite`, etc.) always return
/// `Choice(0)`. `PortableKey` deliberately does not derive [`PartialEq`] — use
/// `ct_eq` explicitly when comparing key material, and prefer the concrete key
/// types extracted via `to_hybrid_*` for cryptographic operations.
///
/// # Example
///
/// Real-world flow: generate keypair → wrap in PortableKey → serialize →
/// deserialize → use for crypto operations.
///
/// ```rust,no_run
/// use latticearc::{PortableKey, UseCase};
///
/// // 1. Generate a hybrid keypair
/// let (pk, sk) = latticearc::generate_hybrid_keypair().expect("keygen");
///
/// // 2. Wrap in PortableKey (UseCase determines algorithm automatically)
/// let (portable_pk, portable_sk) =
///     PortableKey::from_hybrid_kem_keypair(UseCase::FileStorage, &pk, &sk)
///         .expect("wrap");
///
/// // 3. Serialize (JSON for files/REST, CBOR for wire/storage)
/// let json = portable_pk.to_json().expect("serialize");
/// let cbor = portable_pk.to_cbor().expect("serialize");
///
/// // 4. Deserialize and extract for crypto operations
/// let restored_pk = PortableKey::from_json(&json)
///     .expect("deserialize")
///     .to_hybrid_public_key()
///     .expect("extract");
/// ```
/// `derive(Clone)` is intentionally NOT implemented. When
/// `key_type == Secret`, the inner [`KeyData`] holds base64 of
/// secret-key bytes; an implicit clone would silently double the heap
/// regions holding secret material. Use [`Self::clone_for_transmission`]
/// for the audited, explicit duplication path.
#[derive(Serialize, Deserialize)]
pub struct PortableKey {
    /// Format version (currently `1`).
    pub(super) version: u32,

    // --- Primary identifiers (at least one required) ---
    /// Use case that determined algorithm selection.
    /// This is how the library's API works: users pick a use case,
    /// the policy engine selects the optimal algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) use_case: Option<crate::types::types::UseCase>,

    /// Security level (NIST Level 1/3/5). If both `use_case` and
    /// `security_level` are set, `security_level` takes precedence
    /// for algorithm resolution (matching `CryptoConfig` behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) security_level: Option<crate::types::types::SecurityLevel>,

    /// Resolved algorithm identifier. Auto-derived from `use_case` or
    /// `security_level` at creation time. Stored for version-stability —
    /// if the policy engine mapping changes in a future release, existing
    /// keys still parse correctly using this field.
    pub(super) algorithm: KeyAlgorithm,

    /// Key type (public, secret, symmetric).
    pub(super) key_type: KeyType,
    /// Key material (single or composite).
    pub(super) key_data: KeyData,
    /// Creation timestamp (UTC, ISO 8601).
    pub(super) created: DateTime<Utc>,

    /// Optional informational expiry timestamp.
    ///
    /// **This field is a convention, not a security gate.**
    /// [`PortableKey::validate`] does NOT refuse a key past `not_after`;
    /// callers should check [`is_expired`](Self::is_expired) themselves
    /// before using the key.
    ///
    /// To convert this into a tamper-resistant security gate later, the
    /// field must be added to [`encryption_aad`](Self::encryption_aad) and
    /// `ENCRYPTED_ENVELOPE_VERSION` bumped — an attacker who already holds
    /// the encrypted envelope can otherwise edit a plaintext `not_after`
    /// field freely (it isn't part of the AEAD-authenticated data today).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) not_after: Option<DateTime<Utc>>,

    /// Open metadata map for enterprise extensions.
    /// Enterprise crates store additional fields (expiry, hardware binding,
    /// dimensions, etc.) here via extension traits. The base library preserves
    /// all entries during roundtrips without interpretation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) metadata: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for PortableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_data_display = match self.key_type {
            KeyType::Secret | KeyType::Symmetric => "[REDACTED]",
            KeyType::Public => "[key data]",
        };

        f.debug_struct("PortableKey")
            .field("version", &self.version)
            .field("use_case", &self.use_case)
            .field("security_level", &self.security_level)
            .field("algorithm", &self.algorithm)
            .field("key_type", &self.key_type)
            .field("key_data", &key_data_display)
            .field("created", &self.created)
            .field("not_after", &self.not_after)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl subtle::ConstantTimeEq for PortableKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Metadata fields are serialized in plaintext on the wire (version,
        // algorithm identifiers, timestamps, extension map). Their equality
        // is not a secret, so a non-CT short-circuit here is intentional —
        // it avoids needlessly comparing key material when metadata already
        // differs.
        if self.version != other.version
            || self.algorithm != other.algorithm
            || self.key_type != other.key_type
            || self.use_case != other.use_case
            || self.security_level != other.security_level
            || self.created != other.created
            || self.not_after != other.not_after
            || self.metadata != other.metadata
        {
            return subtle::Choice::from(0);
        }

        // Key material: the CT-sensitive field.
        self.key_data.ct_eq(&other.key_data)
    }
}

/// Resolve a `UseCase` to a `KeyAlgorithm` for encryption keys.
///
/// This mirrors the `CryptoPolicyEngine::recommend_encryption_scheme` mapping.
///
/// `pub(super)`: exercised directly by `key_format::tests_b`.
#[must_use]
pub(super) fn resolve_use_case_algorithm(use_case: crate::types::types::UseCase) -> KeyAlgorithm {
    use crate::types::types::UseCase;
    match use_case {
        // Level 1 (128-bit)
        UseCase::IoTDevice => KeyAlgorithm::HybridMlKem512X25519,
        // Level 3 (192-bit) — most use cases
        UseCase::SecureMessaging
        | UseCase::VpnTunnel
        | UseCase::ApiSecurity
        | UseCase::DatabaseEncryption
        | UseCase::ConfigSecrets
        | UseCase::SessionToken
        | UseCase::AuditLog
        | UseCase::Authentication
        | UseCase::FinancialTransactions
        | UseCase::BlockchainTransaction
        | UseCase::FirmwareSigning
        | UseCase::DigitalCertificate
        | UseCase::LegalDocuments => KeyAlgorithm::HybridMlKem768X25519,
        // Level 5 (256-bit) — long-term / regulated
        UseCase::EmailEncryption
        | UseCase::FileStorage
        | UseCase::CloudStorage
        | UseCase::BackupArchive
        | UseCase::KeyExchange
        | UseCase::HealthcareRecords
        | UseCase::GovernmentClassified
        | UseCase::PaymentCard => KeyAlgorithm::HybridMlKem1024X25519,
    }
}

/// Resolve a `SecurityLevel` to a `KeyAlgorithm` for encryption keys.
///
/// `pub(super)`: exercised directly by `key_format::tests_b`.
#[must_use]
pub(super) fn resolve_security_level_algorithm(
    level: crate::types::types::SecurityLevel,
) -> KeyAlgorithm {
    use crate::types::types::SecurityLevel;
    match level {
        SecurityLevel::Standard => KeyAlgorithm::HybridMlKem512X25519,
        SecurityLevel::High => KeyAlgorithm::HybridMlKem768X25519,
        SecurityLevel::Maximum => KeyAlgorithm::HybridMlKem1024X25519,
    }
}

impl PortableKey {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Audited, explicit duplication for transmission / persistence
    /// flows that genuinely need a second instance.
    ///
    /// `derive(Clone)` is intentionally NOT implemented (Pattern 5
    /// anti-pattern 2: secret types must not silently duplicate via
    /// the standard `Clone` trait). When `key_type == Secret`, the
    /// inner `KeyData` holds base64 of secret-key bytes; the
    /// duplicated `String` lands in a fresh heap region that the
    /// custom `Drop` impl below will zeroize, but the duplication
    /// itself is a real moment in the lifetime of the secret and
    /// callers must be deliberate about it.
    #[must_use]
    pub fn clone_for_transmission(&self) -> Self {
        Self {
            version: self.version,
            use_case: self.use_case,
            security_level: self.security_level,
            algorithm: self.algorithm,
            key_type: self.key_type,
            key_data: self.key_data.clone_for_transmission(),
            metadata: self.metadata.clone(),
            created: self.created,
            not_after: self.not_after,
        }
    }

    /// Returns the optional informational expiry timestamp, if any.
    ///
    /// **This field is a convention, not a security gate.** See the
    /// field documentation on [`PortableKey`] for the rationale.
    #[must_use]
    pub const fn not_after(&self) -> Option<DateTime<Utc>> {
        self.not_after
    }

    /// Set or clear the optional informational expiry timestamp.
    ///
    /// **Informational only** — `validate()` does not refuse a key past
    /// `not_after`. Callers requiring enforcement must check
    /// [`is_expired`](Self::is_expired) before using the key.
    pub const fn set_not_after(&mut self, not_after: Option<DateTime<Utc>>) {
        self.not_after = not_after;
    }

    /// Returns `true` when `not_after` is set and is less than or equal to
    /// the supplied `now` instant.
    ///
    /// Pass [`Utc::now()`] for the typical wall-clock check, or a fixed
    /// instant for deterministic tests. Returns `false` when `not_after`
    /// is `None` (no declared expiry).
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.not_after.is_some_and(|t| t <= now)
    }

    /// Convenience: [`is_expired_at`](Self::is_expired_at) using `Utc::now()`.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    /// Create a key identified by use case. Algorithm is auto-derived.
    ///
    /// This is the recommended constructor — it mirrors how the library's
    /// API works: users pick a use case, the policy engine selects the
    /// optimal algorithm.
    #[must_use]
    pub fn for_use_case(
        use_case: crate::types::types::UseCase,
        key_type: KeyType,
        key_data: KeyData,
    ) -> Self {
        let algorithm = resolve_use_case_algorithm(use_case);
        Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        }
    }

    /// Create a key identified by security level. Algorithm is auto-derived.
    #[must_use]
    pub fn for_security_level(
        level: crate::types::types::SecurityLevel,
        key_type: KeyType,
        key_data: KeyData,
    ) -> Self {
        let algorithm = resolve_security_level_algorithm(level);
        Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: Some(level),
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        }
    }

    /// Create with both use case and security level.
    /// `security_level` takes precedence for algorithm resolution.
    #[must_use]
    pub fn for_use_case_with_level(
        use_case: crate::types::types::UseCase,
        level: crate::types::types::SecurityLevel,
        key_type: KeyType,
        key_data: KeyData,
    ) -> Self {
        let algorithm = resolve_security_level_algorithm(level);
        Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: Some(level),
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        }
    }

    /// Low-level constructor with explicit algorithm. For imported keys
    /// from external systems that don't use LatticeArc's UseCase/SecurityLevel.
    #[must_use]
    pub fn new(algorithm: KeyAlgorithm, key_type: KeyType, key_data: KeyData) -> Self {
        // Default `security_level` from the algorithm so the documented
        // struct invariant ("at least one of `use_case` or
        // `security_level` must be present") holds even for this low-
        // level constructor used by external-system imports. Callers
        // that have use-case semantics should prefer `for_use_case` /
        // `for_use_case_with_level`.
        Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: Some(algorithm.nist_security_level()),
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
            not_after: None,
        }
    }

    /// Create with explicit timestamp (for testing / imports).
    #[must_use]
    pub fn with_created(
        algorithm: KeyAlgorithm,
        key_type: KeyType,
        key_data: KeyData,
        created: DateTime<Utc>,
    ) -> Self {
        // Same default-security_level treatment as `Self::new` so this
        // constructor satisfies the same struct invariant.
        Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: Some(algorithm.nist_security_level()),
            algorithm,
            key_type,
            key_data,
            created,
            metadata: BTreeMap::new(),
            not_after: None,
        }
    }

    // --- Core accessors ---

    /// Format version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Use case, if set.
    #[must_use]
    pub fn use_case(&self) -> Option<crate::types::types::UseCase> {
        self.use_case
    }

    /// Security level, if set.
    #[must_use]
    pub fn security_level(&self) -> Option<crate::types::types::SecurityLevel> {
        self.security_level
    }

    /// Resolved algorithm identifier (auto-derived from use_case/security_level).
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Key type (public, secret, symmetric).
    #[must_use]
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Reference to the key data container.
    #[must_use]
    pub fn key_data(&self) -> &KeyData {
        &self.key_data
    }

    /// Creation timestamp.
    #[must_use]
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }

    // --- Metadata accessors ---

    /// Metadata map (read-only).
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.metadata
    }

    /// Insert or update a metadata entry.
    ///
    /// # Errors
    /// Returns `CoreError::ResourceExceeded` when the key would exceed
    /// [`MAX_METADATA_KEY_LEN`](Self::MAX_METADATA_KEY_LEN), the
    /// serialized value would exceed
    /// [`MAX_METADATA_VALUE_JSON_LEN`](Self::MAX_METADATA_VALUE_JSON_LEN),
    /// or inserting a new key would push the map past
    /// [`MAX_METADATA_ENTRIES`](Self::MAX_METADATA_ENTRIES). Returning
    /// `Result` instead of silently dropping prevents enterprise crates
    /// from believing they stored an entry that the format-layer
    /// validator would later reject.
    pub fn set_metadata(&mut self, key: String, value: serde_json::Value) -> Result<()> {
        if key.len() > Self::MAX_METADATA_KEY_LEN {
            return Err(CoreError::ResourceExceeded(format!(
                "metadata key length {} exceeds maximum {}",
                key.len(),
                Self::MAX_METADATA_KEY_LEN
            )));
        }
        let value_len = serde_json::to_string(&value)
            .map(|s| s.len())
            .unwrap_or(Self::MAX_METADATA_VALUE_JSON_LEN.saturating_add(1));
        if value_len > Self::MAX_METADATA_VALUE_JSON_LEN {
            return Err(CoreError::ResourceExceeded(format!(
                "metadata value JSON length {} exceeds maximum {}",
                value_len,
                Self::MAX_METADATA_VALUE_JSON_LEN
            )));
        }
        if !self.metadata.contains_key(&key) && self.metadata.len() >= Self::MAX_METADATA_ENTRIES {
            return Err(CoreError::ResourceExceeded(format!(
                "metadata entry count {} would exceed maximum {}",
                self.metadata.len().saturating_add(1),
                Self::MAX_METADATA_ENTRIES
            )));
        }
        self.metadata.insert(key, value);
        Ok(())
    }

    /// Set a human-readable label in metadata.
    ///
    /// # Errors
    /// Returns `CoreError::ResourceExceeded` if the label, when stored
    /// as a JSON string, would exceed
    /// [`MAX_METADATA_VALUE_JSON_LEN`](Self::MAX_METADATA_VALUE_JSON_LEN).
    pub fn set_label(&mut self, label: impl Into<String>) -> Result<()> {
        self.set_metadata("label".to_string(), serde_json::Value::String(label.into()))
    }

    /// Get the label from metadata, if any.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.metadata.get("label").and_then(|v| v.as_str())
    }
}
