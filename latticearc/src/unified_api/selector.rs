//! Cryptographic Policy Engine
//!
//! Provides policy-based selection of encryption and signature schemes
//! based on data characteristics, security requirements, and performance preferences.
//! Depends on `unified_api::crypto_types` for type-safe scheme enums.

use crate::types::{
    CryptoContext, PerformancePreference, SecurityLevel, UseCase,
    config::CoreConfig,
    error::{Result, TypeError},
    traits::{DataCharacteristics, PatternType, SchemeSelector},
};
use crate::unified_api::crypto_types::{DecryptKey, EncryptKey, EncryptionScheme};

// =============================================================================
// PERFORMANCE OPTIMIZATION THRESHOLDS
// =============================================================================

/// Data-size threshold (in bytes) below which the legacy size-conditioned
/// branch in [`CryptoPolicyEngine::select_encryption_scheme`] would
/// have downgraded a caller-declared [`SecurityLevel::High`]
/// (ML-KEM-768) to ML-KEM-512 under [`PerformancePreference::Memory`].
/// That downgrade now **refuses** instead of silently weakening the
/// caller's contract.
///
/// **What actually happens at runtime**:
///
/// | `security_level` | `performance_preference` | data conditions       | result |
/// |------------------|--------------------------|-----------------------|--------|
/// | `Standard`       | any                      | any                   | `Ok(ML-KEM-512)` (default for Standard — no L3 contract to honor) |
/// | `High`           | `Speed`                  | random pattern        | `Err(ConfigurationError)` — refuses L1 silent weakening |
/// | `High`           | `Memory`                 | data size < threshold | `Err(ConfigurationError)` — refuses L1 silent weakening |
/// | `High`           | otherwise                | otherwise             | `Ok(ML-KEM-768)` — caller's declared level honored |
/// | `Maximum`        | any                      | any                   | `Ok(ML-KEM-1024)` — never weakened |
///
/// **Rationale for refusal**: a caller declaring `SecurityLevel::High`
/// has a security-relevant reason to want exactly L3. The pre-fix
/// behavior emitted a `tracing::warn!` and returned an L1 string —
/// observability is not contract enforcement, and operators routinely
/// miss warn-level events. Refusing forces the caller to either drop
/// to `Standard` explicitly (acknowledging the optimization) or use
/// the typed alternative [`CryptoPolicyEngine::select_encryption_scheme_typed`]
/// which has never carried the downgrade path.
///
/// **Note**: this threshold gates ONLY the Memory-branch refusal in
/// the legacy string-based selector. It has no effect on the typed
/// API or on caller-declared `Standard` / `Maximum` levels.
pub const ML_KEM_DOWNGRADE_REFUSAL_THRESHOLD: usize = 4096;

/// Main cryptographic policy engine.
///
/// Analyzes data and configuration to recommend optimal cryptographic schemes
/// based on security policies, use cases, and runtime context.
///
/// # Modes
///
/// The engine supports three cryptographic modes:
/// - **Hybrid** (default): ML-KEM + X25519 + AES-256-GCM for defense-in-depth
/// - **PQ-Only**: ML-KEM + AES-256-GCM for pure post-quantum security
/// - **Classical**: X25519 + AES-256-GCM for legacy compatibility
pub struct CryptoPolicyEngine;

impl Default for CryptoPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoPolicyEngine {
    /// Creates a new `CryptoPolicyEngine` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Recommends a cryptographic scheme based on use case.
    /// All encryption use cases default to hybrid for quantum safety.
    ///
    /// each use case is pre-mapped to a security
    /// level (e.g. `IoTDevice` → ML-KEM-512, `EmailEncryption` →
    /// ML-KEM-1024). The `config.security_level` is **not** used to
    /// override the use-case mapping — that's a deliberate design
    /// choice (use cases are self-documenting and a per-use-case
    /// mapping prevents configuration drift). However, when a caller
    /// supplies a non-default `config.security_level`, we now log a
    /// `tracing::debug!` so it's visible in audit-trail pipelines that
    /// the override was ignored. Callers wanting strict-level routing
    /// should use `select_pq_encryption_scheme` / `select_encryption_scheme`
    /// (level-driven), or call `force_scheme` to bypass use-case
    /// mapping entirely.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    #[must_use = "scheme recommendation should be used for algorithm selection"]
    pub fn recommend_scheme(use_case: &UseCase, config: &CoreConfig) -> Result<String> {
        // surface the no-op so it's not silent.
        // Default `SecurityLevel` is `High`; anything else means the
        // caller passed it explicitly and would reasonably expect it
        // to influence selection. It does not — log so the divergence
        // is visible.
        if config.security_level != SecurityLevel::default() {
            tracing::debug!(
                use_case = ?use_case,
                requested_level = ?config.security_level,
                "recommend_scheme: config.security_level is not consulted in the use-case path; \
                 use select_pq_encryption_scheme or force_scheme for level-driven routing"
            );
        }
        match *use_case {
            // Communication
            UseCase::SecureMessaging => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::EmailEncryption => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::VpnTunnel => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::ApiSecurity => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),

            // Storage
            UseCase::FileStorage => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::DatabaseEncryption => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::CloudStorage => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::BackupArchive => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::ConfigSecrets => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),

            // Authentication & Identity
            UseCase::Authentication => Ok("hybrid-ml-dsa-87-ed25519".to_string()),
            UseCase::SessionToken => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::DigitalCertificate => Ok("hybrid-ml-dsa-87-ed25519".to_string()),
            UseCase::KeyExchange => Ok("hybrid-ml-kem-1024-x25519".to_string()),

            // Financial & Legal
            UseCase::FinancialTransactions => Ok("hybrid-ml-dsa-65-ed25519".to_string()),
            UseCase::LegalDocuments => Ok("hybrid-ml-dsa-87-ed25519".to_string()),
            UseCase::BlockchainTransaction => Ok("hybrid-ml-dsa-65-ed25519".to_string()),

            // Regulated Industries
            UseCase::HealthcareRecords => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::GovernmentClassified => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::PaymentCard => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),

            // IoT & Embedded
            UseCase::IoTDevice => Ok("hybrid-ml-kem-512-aes-256-gcm".to_string()),
            UseCase::FirmwareSigning => Ok("hybrid-ml-dsa-65-ed25519".to_string()),

            // General Purpose
            UseCase::AuditLog => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
        }
    }

    /// Returns the scheme string for a specific scheme category.
    ///
    /// For `PostQuantum`, returns a parseable PQ-only encryption scheme string
    /// that maps to `EncryptionScheme::PqMlKem768Aes256Gcm`.
    #[must_use]
    pub fn force_scheme(scheme: &crate::types::CryptoScheme) -> String {
        match *scheme {
            crate::types::CryptoScheme::Hybrid => DEFAULT_ENCRYPTION_SCHEME.to_string(),
            crate::types::CryptoScheme::Symmetric => "aes-256-gcm".to_string(),
            crate::types::CryptoScheme::SymmetricChaCha20 => "chacha20-poly1305".to_string(),
            crate::types::CryptoScheme::Asymmetric => "pq-ml-dsa-65".to_string(),
            crate::types::CryptoScheme::PostQuantum => PQ_ENCRYPTION_768.to_string(),
        }
    }

    /// Select PQ-only encryption scheme (no classical component).
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    #[must_use = "scheme selection should be used for algorithm configuration"]
    pub fn select_pq_encryption_scheme(config: &CoreConfig) -> Result<String> {
        match config.security_level {
            SecurityLevel::Standard => Ok(PQ_ENCRYPTION_512.to_string()),
            SecurityLevel::High => Ok(PQ_ENCRYPTION_768.to_string()),
            SecurityLevel::Maximum => Ok(PQ_ENCRYPTION_1024.to_string()),
        }
    }

    /// Select PQ-only signature scheme (no classical component).
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    #[must_use = "scheme selection should be used for algorithm configuration"]
    pub fn select_pq_signature_scheme(config: &CoreConfig) -> Result<String> {
        match config.security_level {
            SecurityLevel::Standard => Ok(PQ_SIGNATURE_44.to_string()),
            SecurityLevel::High => Ok(PQ_SIGNATURE_65.to_string()),
            SecurityLevel::Maximum => Ok(PQ_SIGNATURE_87.to_string()),
        }
    }

    /// Analyzes data characteristics for scheme selection.
    #[must_use]
    pub fn analyze_data_characteristics(data: &[u8]) -> DataCharacteristics {
        let size = data.len();
        let entropy = calculate_entropy(data);
        let pattern_type = detect_pattern_type(data);

        DataCharacteristics { size, entropy, pattern_type }
    }

    /// Selects encryption scheme based on data, config, and optional use case.
    ///
    /// When `hardware_acceleration` is `false` and no use case is specified:
    ///   * `SecurityLevel::Standard` callers receive `chacha20-poly1305`
    ///     (fast in software without AES-NI). This is symmetric-only.
    ///   * `SecurityLevel::High` or `Maximum` callers receive
    ///     `Err(ConfigurationError)` — refusing to silently substitute a
    ///     symmetric-only scheme for a caller-declared post-quantum tier.
    ///
    /// When data is provided, analyzes data characteristics to optimize
    /// scheme selection for the data's entropy and size patterns.
    ///
    /// # Errors
    ///
    /// Returns `TypeError::ConfigurationError` when:
    ///   * `hardware_acceleration = false` and `security_level != Standard`
    ///     (refusal of silent post-quantum strip), or
    ///   * the caller declared `SecurityLevel::High` and the size-conditioned
    ///     branch would otherwise downgrade ML-KEM-768 to ML-KEM-512.
    pub fn select_encryption_scheme(
        data: &[u8],
        config: &CoreConfig,
        use_case: Option<&UseCase>,
    ) -> Result<String> {
        if let Some(use_case) = use_case {
            return Self::recommend_scheme(use_case, config);
        }

        // `hardware_acceleration = false` opts into a software-only AEAD
        // fallback (ChaCha20-Poly1305). That scheme is symmetric-only:
        // `EncryptionScheme::ChaCha20Poly1305.requires_symmetric_key()` is
        // `true` and there is no ML-KEM component. Returning it to a caller
        // that declared `SecurityLevel::High` or `Maximum` would silently
        // substitute non-PQ for PQ, so refuse those configurations and
        // require the caller to lower the level (or use the typed selector
        // which doesn't consult this flag).
        if !config.hardware_acceleration {
            if !matches!(config.security_level, SecurityLevel::Standard) {
                return Err(TypeError::ConfigurationError(
                    "hardware_acceleration = false with SecurityLevel::High or \
                     Maximum would substitute symmetric-only ChaCha20-Poly1305 \
                     for the requested hybrid ML-KEM scheme; lower \
                     security_level to Standard to opt into the symmetric \
                     fallback, or use select_encryption_scheme_typed."
                        .to_string(),
                ));
            }
            return Ok(CHACHA20_POLY1305.to_string());
        }

        // Data-aware adjustments when data is non-empty.
        //
        // Previous behavior: under
        // `(Speed, Random)` or `(Memory, small)` and a caller-declared
        // `SecurityLevel::High` (NIST L3 / ML-KEM-768), the engine
        // would silently downgrade to ML-KEM-512 (NIST L1) and emit
        // a `tracing::warn!`. The L3 audit (post-85e2bd79e) flagged
        // the warn-only path as a footgun — observability pipelines
        // are not contract enforcement, and a caller declaring L3 has
        // a security-relevant reason to want exactly L3. The function
        // now returns `Err(ConfigurationError)` instead of returning
        // an L1 string, refusing to silently weaken the caller's
        // requested level. `PerformancePreference::Balanced` and
        // `SecurityLevel::Maximum` are unaffected.
        //
        // Migration for existing callers that *do* want the
        // optimization: pre-relax `config.security_level` to
        // `SecurityLevel::Standard` before calling, OR use the typed
        // alternative [`select_encryption_scheme_typed`] which never
        // performs the downgrade in the first place.
        if !data.is_empty() {
            let characteristics = Self::analyze_data_characteristics(data);

            match (&config.performance_preference, &characteristics.pattern_type) {
                // High-entropy data with speed preference: caller would
                // be best served by ML-KEM-512, but they declared L3.
                // Refuse rather than silently weaken.
                (PerformancePreference::Speed, PatternType::Random) => {
                    if matches!(config.security_level, SecurityLevel::High) {
                        return Err(TypeError::ConfigurationError(
                            "performance_preference = Speed + Random data pattern would \
                             require downgrading caller-declared SecurityLevel::High \
                             (ML-KEM-768) to ML-KEM-512; use SecurityLevel::Standard \
                             explicitly if the optimization is acceptable, or use \
                             select_encryption_scheme_typed which never downgrades"
                                .to_string(),
                        ));
                    }
                }
                // Memory-constrained with small data: same refusal.
                (PerformancePreference::Memory, _)
                    if data.len() < ML_KEM_DOWNGRADE_REFUSAL_THRESHOLD =>
                {
                    if matches!(config.security_level, SecurityLevel::High) {
                        return Err(TypeError::ConfigurationError(
                            "performance_preference = Memory + small data \
                             (< ML_KEM_DOWNGRADE_REFUSAL_THRESHOLD bytes) would require \
                             downgrading caller-declared SecurityLevel::High (ML-KEM-768) \
                             to ML-KEM-512; use SecurityLevel::Standard explicitly if \
                             the optimization is acceptable, or use \
                             select_encryption_scheme_typed which never downgrades"
                                .to_string(),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(Self::select_for_security_level(config))
    }

    /// Select scheme based only on security level (no data analysis).
    fn select_for_security_level(config: &CoreConfig) -> String {
        match &config.security_level {
            SecurityLevel::Maximum => HYBRID_ENCRYPTION_1024.to_string(),
            SecurityLevel::High => HYBRID_ENCRYPTION_768.to_string(),
            SecurityLevel::Standard => HYBRID_ENCRYPTION_512.to_string(),
        }
    }

    /// Selects a signature scheme based on the configuration's security level.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    #[must_use = "scheme selection should be used for algorithm configuration"]
    pub fn select_signature_scheme(config: &CoreConfig) -> Result<String> {
        match &config.security_level {
            SecurityLevel::Maximum => Ok(HYBRID_SIGNATURE_87.to_string()),
            SecurityLevel::High => Ok(HYBRID_SIGNATURE_65.to_string()),
            SecurityLevel::Standard => Ok(HYBRID_SIGNATURE_44.to_string()),
        }
    }

    /// Select encryption scheme based on runtime performance metrics.
    ///
    /// Implementation: Thresholds on `memory_usage_mb` and `encryption_speed_ms`
    /// select smaller KEM parameters when resources are constrained.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn adaptive_selection(
        data: &[u8],
        performance_metrics: &PerformanceMetrics,
        config: &CoreConfig,
    ) -> Result<String> {
        let characteristics = Self::analyze_data_characteristics(data);
        let base_scheme = Self::select_encryption_scheme(data, config, None)?;

        // Runtime-pressure adjustments. Important: the small-data
        // `(Memory, High)` case never reaches this match — it is
        // already rejected upstream by the `select_encryption_scheme`
        // call at the top of this function (the `(Memory, _) if data.len()
        // < ML_KEM_DOWNGRADE_REFUSAL_THRESHOLD` branch in
        // `select_encryption_scheme`). The Memory arm here therefore only
        // fires for data ≥ threshold, where it preserves the caller's
        // L3 pin (`ML-KEM-768`) and is a true no-op pass-through — no
        // security weakening.
        //
        // The Speed branch refuses with `Err` when measured encryption
        // is slow on repetitive data at L3, mirroring the refusal in
        // `select_encryption_scheme`. `Maximum` is unaffected; no
        // downgrade path was ever wired for it.
        match (&config.performance_preference, performance_metrics) {
            (PerformancePreference::Memory, metrics)
                if metrics.memory_usage_mb > 500.0
                    && matches!(config.security_level, SecurityLevel::High) =>
            {
                Ok(HYBRID_ENCRYPTION_768.to_string())
            }
            (PerformancePreference::Speed, metrics)
                if metrics.encryption_speed_ms > 1000.0
                    && matches!(characteristics.pattern_type, PatternType::Repetitive)
                    && matches!(config.security_level, SecurityLevel::High) =>
            {
                Err(TypeError::ConfigurationError(
                    "adaptive_selection: measured encryption_speed_ms > 1000 + repetitive \
                     data pattern + Speed preference would require downgrading caller-declared \
                     SecurityLevel::High (ML-KEM-768) to ML-KEM-512; use SecurityLevel::Standard \
                     explicitly if the optimization is acceptable, or reduce the runtime \
                     pressure before invoking adaptive_selection"
                        .to_string(),
                ))
            }
            _ => Ok(base_scheme),
        }
    }

    /// Returns the default hybrid scheme (no context analysis).
    #[must_use]
    pub fn default_scheme() -> &'static str {
        DEFAULT_ENCRYPTION_SCHEME
    }

    // =========================================================================
    // Type-Safe API (returns EncryptionScheme enum, not String)
    // =========================================================================

    /// Recommend an encryption scheme for a use case, returning a type-safe enum.
    ///
    /// Only returns encryption-capable schemes. Signature-only use cases
    /// (Authentication, DigitalCertificate, etc.) return the default hybrid
    /// encryption scheme since they cannot be used for encryption.
    ///
    /// # Errors
    ///
    /// Returns `TypeError` if the use case cannot be mapped to an encryption scheme.
    pub fn recommend_encryption_scheme(
        use_case: &UseCase,
        _config: &CoreConfig,
    ) -> Result<EncryptionScheme> {
        // _config is retained for API stability; scheme selection is use-case-driven.
        match *use_case {
            // Communication
            UseCase::SecureMessaging | UseCase::VpnTunnel | UseCase::ApiSecurity => {
                Ok(EncryptionScheme::HybridMlKem768Aes256Gcm)
            }

            UseCase::EmailEncryption => Ok(EncryptionScheme::HybridMlKem1024Aes256Gcm),

            // Storage
            UseCase::FileStorage | UseCase::CloudStorage | UseCase::BackupArchive => {
                Ok(EncryptionScheme::HybridMlKem1024Aes256Gcm)
            }

            UseCase::DatabaseEncryption
            | UseCase::ConfigSecrets
            | UseCase::SessionToken
            | UseCase::AuditLog => Ok(EncryptionScheme::HybridMlKem768Aes256Gcm),

            // Regulated Industries
            UseCase::HealthcareRecords | UseCase::GovernmentClassified | UseCase::PaymentCard => {
                Ok(EncryptionScheme::HybridMlKem1024Aes256Gcm)
            }

            // Key Exchange
            UseCase::KeyExchange => Ok(EncryptionScheme::HybridMlKem1024Aes256Gcm),

            // IoT (constrained)
            UseCase::IoTDevice => Ok(EncryptionScheme::HybridMlKem512Aes256Gcm),

            // Signature-only use cases: return default encryption scheme
            // (callers should use sign_with_key() instead, but we don't error here)
            UseCase::Authentication
            | UseCase::DigitalCertificate
            | UseCase::FinancialTransactions
            | UseCase::LegalDocuments
            | UseCase::BlockchainTransaction
            | UseCase::FirmwareSigning => Ok(EncryptionScheme::HybridMlKem768Aes256Gcm),
        }
    }

    /// Select a hybrid encryption scheme based on security level.
    ///
    /// Always returns a hybrid scheme (`CryptoMode::Hybrid`). For PQ-only
    /// scheme selection, use [`select_encryption_scheme_typed_with_mode`] instead.
    #[must_use]
    pub fn select_encryption_scheme_typed(config: &CoreConfig) -> EncryptionScheme {
        Self::select_encryption_scheme_typed_with_mode(
            config,
            crate::types::types::CryptoMode::Hybrid,
        )
    }

    /// Select encryption scheme with an explicit `CryptoMode`.
    ///
    /// This is the primary typed scheme selector that respects the crypto mode.
    #[must_use]
    pub fn select_encryption_scheme_typed_with_mode(
        config: &CoreConfig,
        mode: crate::types::types::CryptoMode,
    ) -> EncryptionScheme {
        use crate::types::types::CryptoMode;

        match mode {
            CryptoMode::PqOnly => match &config.security_level {
                SecurityLevel::Maximum => EncryptionScheme::PqMlKem1024Aes256Gcm,
                SecurityLevel::High => EncryptionScheme::PqMlKem768Aes256Gcm,
                SecurityLevel::Standard => EncryptionScheme::PqMlKem512Aes256Gcm,
            },
            CryptoMode::Hybrid => match &config.security_level {
                SecurityLevel::Maximum => EncryptionScheme::HybridMlKem1024Aes256Gcm,
                SecurityLevel::High => EncryptionScheme::HybridMlKem768Aes256Gcm,
                SecurityLevel::Standard => EncryptionScheme::HybridMlKem512Aes256Gcm,
            },
        }
    }

    /// Validate that the key variant matches the scheme requirements.
    ///
    /// Returns `Ok(())` if the key type is compatible with the scheme,
    /// or `Err(TypeError::ConfigurationError)` describing the mismatch.
    ///
    /// # Errors
    ///
    /// Returns an error if the key type doesn't match the scheme requirements.
    pub fn validate_key_matches_scheme(
        key: &EncryptKey<'_>,
        scheme: &EncryptionScheme,
    ) -> Result<()> {
        match (key, scheme) {
            // Symmetric key for symmetric scheme — OK
            (EncryptKey::Symmetric(_), s) if s.requires_symmetric_key() => Ok(()),
            // Hybrid key for hybrid scheme — check level
            (EncryptKey::Hybrid(pk), s) if s.requires_hybrid_key() => {
                if let Some(expected_level) = s.ml_kem_level()
                    && pk.security_level() != expected_level
                {
                    return Err(TypeError::ConfigurationError(format!(
                        "Scheme '{}' requires {} key, but the provided key \
                         was generated at {} level. Use \
                         generate_hybrid_keypair_with_level({:?}).",
                        scheme,
                        expected_level.name(),
                        pk.security_level().name(),
                        expected_level
                    )));
                }
                Ok(())
            }
            // PQ-only key for PQ-only scheme — check level
            (EncryptKey::PqOnly(pk), s) if s.requires_pq_key() => {
                if let Some(expected_level) = s.ml_kem_level()
                    && pk.security_level() != expected_level
                {
                    return Err(TypeError::ConfigurationError(format!(
                        "Scheme '{}' requires {} key, but the provided PQ-only key \
                         was generated at {} level. Use \
                         generate_pq_keypair_with_level({:?}).",
                        scheme,
                        expected_level.name(),
                        pk.security_level().name(),
                        expected_level
                    )));
                }
                Ok(())
            }
            // Mismatches
            (EncryptKey::Symmetric(_), _) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' requires a hybrid or PQ-only key, \
                 but a symmetric key was provided.",
                scheme
            ))),
            (EncryptKey::Hybrid(_), _) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' does not accept a hybrid key. Expected: {}.",
                scheme,
                if scheme.requires_pq_key() {
                    "EncryptKey::PqOnly"
                } else {
                    "EncryptKey::Symmetric"
                }
            ))),
            (EncryptKey::PqOnly(_), _) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' does not accept a PQ-only key. Expected: {}.",
                scheme,
                if scheme.requires_hybrid_key() {
                    "EncryptKey::Hybrid"
                } else {
                    "EncryptKey::Symmetric"
                }
            ))),
        }
    }

    /// Validate that the decrypt key variant matches the scheme requirements.
    ///
    /// # Errors
    ///
    /// Returns an error if the key type doesn't match the scheme.
    pub fn validate_decrypt_key_matches_scheme(
        key: &DecryptKey<'_>,
        scheme: &EncryptionScheme,
    ) -> Result<()> {
        match (key, scheme) {
            // Symmetric key for symmetric scheme — OK
            (DecryptKey::Symmetric(_), s) if s.requires_symmetric_key() => Ok(()),
            // Hybrid key for hybrid scheme — check level
            (DecryptKey::Hybrid(sk), s) if s.requires_hybrid_key() => {
                if let Some(expected_level) = s.ml_kem_level()
                    && sk.security_level() != expected_level
                {
                    return Err(TypeError::ConfigurationError(format!(
                        "Scheme '{}' requires {} key, but the provided key \
                         was generated at {} level.",
                        scheme,
                        expected_level.name(),
                        sk.security_level().name(),
                    )));
                }
                Ok(())
            }
            // PQ-only key for PQ-only scheme — check level
            (DecryptKey::PqOnly(sk), s) if s.requires_pq_key() => {
                if let Some(expected_level) = s.ml_kem_level()
                    && sk.security_level() != expected_level
                {
                    return Err(TypeError::ConfigurationError(format!(
                        "Scheme '{}' requires {} key, but the provided PQ-only key \
                         was generated at {} level.",
                        scheme,
                        expected_level.name(),
                        sk.security_level().name(),
                    )));
                }
                Ok(())
            }
            // Mismatches
            (DecryptKey::Symmetric(_), _) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' requires a hybrid or PQ-only secret key, \
                 but a symmetric key was provided.",
                scheme
            ))),
            (DecryptKey::Hybrid(_), _) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' does not accept a hybrid key for decryption. Expected: {}.",
                scheme,
                if scheme.requires_pq_key() {
                    "DecryptKey::PqOnly"
                } else {
                    "DecryptKey::Symmetric"
                }
            ))),
            (DecryptKey::PqOnly(_), _) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' does not accept a PQ-only key for decryption. Expected: {}.",
                scheme,
                if scheme.requires_hybrid_key() {
                    "DecryptKey::Hybrid"
                } else {
                    "DecryptKey::Symmetric"
                }
            ))),
        }
    }
}

impl SchemeSelector for CryptoPolicyEngine {
    type Error = TypeError;
    fn select_encryption_scheme(
        &self,
        data: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<String, Self::Error> {
        Self::select_encryption_scheme(
            data,
            &CoreConfig {
                security_level: ctx.security_level,
                performance_preference: ctx.performance_preference.clone(),
                hardware_acceleration: ctx.hardware_acceleration,
                ..CoreConfig::default()
            },
            ctx.use_case.as_ref(),
        )
    }

    fn select_signature_scheme(
        &self,
        ctx: &CryptoContext,
    ) -> std::result::Result<String, Self::Error> {
        Self::select_signature_scheme(&CoreConfig {
            security_level: ctx.security_level,
            performance_preference: ctx.performance_preference.clone(),
            hardware_acceleration: ctx.hardware_acceleration,
            ..CoreConfig::default()
        })
    }

    fn analyze_data_characteristics(&self, data: &[u8]) -> DataCharacteristics {
        Self::analyze_data_characteristics(data)
    }
}

/// Calculates the Shannon entropy of the data in bits per byte.
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        let index = usize::from(byte);
        if let Some(count) = frequency.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "precision loss is intentional in this measurement/heuristic path"
    )]
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in &frequency {
        if count > 0 {
            #[expect(
                clippy::cast_precision_loss,
                reason = "precision loss is intentional in this measurement/heuristic path"
            )]
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Detects the pattern type of the input data.
fn detect_pattern_type(data: &[u8]) -> PatternType {
    if data.is_empty() {
        return PatternType::Random;
    }

    let entropy = calculate_entropy(data);

    if entropy > 7.5 {
        return PatternType::Random;
    }

    let mut is_text = true;
    for &byte in data {
        if !(byte.is_ascii_graphic() || byte.is_ascii_whitespace()) {
            is_text = false;
            break;
        }
    }

    if is_text && entropy > 4.0 {
        return PatternType::Text;
    }

    let mut repetitive = true;
    if data.len() > 8 {
        let chunk_size = std::cmp::min(8, data.len() / 4);
        let first_chunk = data.get(..chunk_size);

        if let Some(first) = first_chunk {
            for chunk in data.chunks(chunk_size).skip(1) {
                if chunk != first {
                    repetitive = false;
                    break;
                }
            }
        } else {
            repetitive = false;
        }
    } else {
        repetitive = false;
    }

    if repetitive {
        return PatternType::Repetitive;
    }

    let has_structure = data.windows(4).any(|window| {
        let w0 = window.first().copied().unwrap_or(0);
        let w1 = window.get(1).copied().unwrap_or(0);
        let w2 = window.get(2).copied().unwrap_or(0);
        let w3 = window.get(3).copied().unwrap_or(0);
        w0.wrapping_add(1) == w1 && w1.wrapping_add(1) == w2 && w2.wrapping_add(1) == w3
    });

    if has_structure || entropy < 6.0 { PatternType::Structured } else { PatternType::Binary }
}

// =============================================================================
// SECURITY LEVEL ↔ ML-KEM LEVEL MAPPING
// =============================================================================

use crate::primitives::kem::ml_kem::MlKemSecurityLevel;

/// Map `MlKemSecurityLevel` to the corresponding `SecurityLevel`.
///
/// This is the canonical reverse mapping — the forward direction
/// (`SecurityLevel → MlKemSecurityLevel`) lives in
/// [`expected_ml_kem_level`](crate::unified_api::convenience::pq_kem).
#[must_use]
pub fn ml_kem_level_to_security_level(level: MlKemSecurityLevel) -> SecurityLevel {
    match level {
        MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
        MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
        MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
    }
}

// =============================================================================
// SCHEME CONSTANTS
// =============================================================================

/// Default hybrid encryption scheme - ML-KEM + X25519
pub const DEFAULT_ENCRYPTION_SCHEME: &str = "hybrid-ml-kem-768-aes-256-gcm";
/// Default hybrid signature scheme - ML-DSA + Ed25519
pub const DEFAULT_SIGNATURE_SCHEME: &str = "hybrid-ml-dsa-65-ed25519";

/// Hybrid encryption variant using ML-KEM-512 and AES-256-GCM.
pub const HYBRID_ENCRYPTION_512: &str = "hybrid-ml-kem-512-aes-256-gcm";
/// Hybrid encryption variant using ML-KEM-768 and AES-256-GCM.
pub const HYBRID_ENCRYPTION_768: &str = "hybrid-ml-kem-768-aes-256-gcm";
/// Hybrid encryption variant using ML-KEM-1024 and AES-256-GCM.
pub const HYBRID_ENCRYPTION_1024: &str = "hybrid-ml-kem-1024-aes-256-gcm";

/// Hybrid signature variant using ML-DSA-44 and Ed25519.
pub const HYBRID_SIGNATURE_44: &str = "hybrid-ml-dsa-44-ed25519";
/// Hybrid signature variant using ML-DSA-65 and Ed25519.
pub const HYBRID_SIGNATURE_65: &str = "hybrid-ml-dsa-65-ed25519";
/// Hybrid signature variant using ML-DSA-87 and Ed25519.
pub const HYBRID_SIGNATURE_87: &str = "hybrid-ml-dsa-87-ed25519";

/// PQ-only encryption variant using ML-KEM-512 and AES-256-GCM.
pub const PQ_ENCRYPTION_512: &str = "pq-ml-kem-512-aes-256-gcm";
/// PQ-only encryption variant using ML-KEM-768 and AES-256-GCM.
pub const PQ_ENCRYPTION_768: &str = "pq-ml-kem-768-aes-256-gcm";
/// PQ-only encryption variant using ML-KEM-1024 and AES-256-GCM.
pub const PQ_ENCRYPTION_1024: &str = "pq-ml-kem-1024-aes-256-gcm";

/// PQ-only signature variant using ML-DSA-44.
pub const PQ_SIGNATURE_44: &str = "pq-ml-dsa-44";
/// PQ-only signature variant using ML-DSA-65.
pub const PQ_SIGNATURE_65: &str = "pq-ml-dsa-65";
/// PQ-only signature variant using ML-DSA-87.
pub const PQ_SIGNATURE_87: &str = "pq-ml-dsa-87";

/// Default PQ-only encryption scheme (alias for [`PQ_ENCRYPTION_768`]).
pub const DEFAULT_PQ_ENCRYPTION_SCHEME: &str = PQ_ENCRYPTION_768;
/// Default PQ-only signature scheme (alias for [`PQ_SIGNATURE_65`]).
pub const DEFAULT_PQ_SIGNATURE_SCHEME: &str = PQ_SIGNATURE_65;

/// ChaCha20-Poly1305 symmetric encryption (fast without AES-NI hardware).
pub const CHACHA20_POLY1305: &str = "chacha20-poly1305";

/// Classical symmetric encryption scheme identifier (decrypt compatibility only)
pub const CLASSICAL_AES_GCM: &str = "aes-256-gcm";
/// Classical signature scheme identifier (decrypt compatibility only)
pub const CLASSICAL_ED25519: &str = "ed25519";

/// Runtime performance metrics for adaptive scheme selection.
///
/// Implementation: `CryptoPolicyEngine::adaptive_selection()` — thresholds on `memory_usage_mb` and `encryption_speed_ms`
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Average encryption time in milliseconds.
    /// Consumer: `CryptoPolicyEngine::adaptive_selection()`
    pub encryption_speed_ms: f64,
    /// Current memory usage in megabytes.
    /// Consumer: `CryptoPolicyEngine::adaptive_selection()`
    pub memory_usage_mb: f64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self { encryption_speed_ms: 100.0, memory_usage_mb: 100.0 }
    }
}

// Formal verification with Kani
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proves that `force_scheme` returns a non-empty scheme string for
    /// every CryptoScheme variant. Security property: no scheme category
    /// maps to an empty/undefined algorithm.
    #[kani::proof]
    fn force_scheme_covers_all_variants() {
        let scheme: crate::types::CryptoScheme = kani::any();
        let result = CryptoPolicyEngine::force_scheme(&scheme);
        kani::assert(!result.is_empty(), "force_scheme must return a non-empty scheme string");
    }

    /// Proves that PQ encryption scheme selection succeeds for every
    /// SecurityLevel. Security property: no security level is left
    /// without a post-quantum encryption algorithm.
    #[kani::proof]
    fn select_pq_encryption_covers_all_levels() {
        let level: SecurityLevel = kani::any();
        let config = CoreConfig {
            security_level: level,
            performance_preference: PerformancePreference::Balanced,
            hardware_acceleration: true,
            fallback_enabled: true,
            strict_validation: true,
        };
        let result = CryptoPolicyEngine::select_pq_encryption_scheme(&config);
        kani::assert(
            result.is_ok(),
            "PQ encryption selection must succeed for all security levels",
        );
    }

    /// Proves that PQ signature scheme selection succeeds for every
    /// SecurityLevel. Security property: no security level is left
    /// without a post-quantum signature algorithm.
    #[kani::proof]
    fn select_pq_signature_covers_all_levels() {
        let level: SecurityLevel = kani::any();
        let config = CoreConfig {
            security_level: level,
            performance_preference: PerformancePreference::Balanced,
            hardware_acceleration: true,
            fallback_enabled: true,
            strict_validation: true,
        };
        let result = CryptoPolicyEngine::select_pq_signature_scheme(&config);
        kani::assert(result.is_ok(), "PQ signature selection must succeed for all security levels");
    }

    /// Proves hybrid/general encryption selection succeeds for all SecurityLevels
    /// when no UseCase is specified. Security: no security level lacks a scheme.
    #[kani::proof]
    fn select_encryption_covers_all_levels() {
        let level: SecurityLevel = kani::any();
        let config = CoreConfig {
            security_level: level,
            performance_preference: PerformancePreference::Balanced,
            hardware_acceleration: true,
            fallback_enabled: true,
            strict_validation: true,
        };
        let data = [0u8; 16];
        let result = CryptoPolicyEngine::select_encryption_scheme(&data, &config, None);
        kani::assert(result.is_ok(), "Encryption selection must succeed for all levels");
    }

    /// Proves signature scheme selection succeeds for all SecurityLevels.
    /// Security: no security level lacks a signature algorithm.
    #[kani::proof]
    fn select_signature_covers_all_levels() {
        let level: SecurityLevel = kani::any();
        let config = CoreConfig {
            security_level: level,
            performance_preference: PerformancePreference::Balanced,
            hardware_acceleration: true,
            fallback_enabled: true,
            strict_validation: true,
        };
        let result = CryptoPolicyEngine::select_signature_scheme(&config);
        kani::assert(result.is_ok(), "Signature selection must succeed for all levels");
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test/bench code: unwrap is acceptable when inputs are statically known"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test fns return Result and use assert! macros which expand to panic"
)]
#[expect(
    clippy::float_cmp,
    reason = "exact float comparison is intentional when verifying entropy/threshold constants"
)]
#[expect(
    unused_qualifications,
    reason = "fully-qualified paths kept for clarity in test assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_constants_succeeds() {
        assert_eq!(DEFAULT_ENCRYPTION_SCHEME, "hybrid-ml-kem-768-aes-256-gcm");
        assert_eq!(DEFAULT_SIGNATURE_SCHEME, "hybrid-ml-dsa-65-ed25519");
    }

    #[test]
    fn test_policy_engine_new_succeeds() {
        let engine = CryptoPolicyEngine::new();
        assert!(std::mem::size_of_val(&engine) == 0);
    }

    #[test]
    fn test_default_scheme_succeeds() {
        assert_eq!(CryptoPolicyEngine::default_scheme(), DEFAULT_ENCRYPTION_SCHEME);
    }

    #[test]
    fn test_recommend_scheme_secure_messaging_returns_hybrid_scheme_succeeds() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-768-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_encryption_scheme_maximum_security_succeeds() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let data = b"test data";
        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
        assert_eq!(scheme, "hybrid-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_analyze_empty_data_succeeds() {
        let data: &[u8] = &[];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.size, 0);
        assert_eq!(characteristics.entropy, 0.0);
    }

    #[test]
    fn test_analyze_repetitive_data_returns_low_entropy_succeeds() {
        let data = vec![0u8; 1000];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert!(characteristics.entropy < 1.0);
        assert_eq!(characteristics.pattern_type, PatternType::Repetitive);
    }

    // =========================================================================
    // Parameter Influence Tests (Audit 4.12)
    // =========================================================================

    #[test]
    fn test_hardware_acceleration_false_standard_selects_chacha20_scheme_succeeds() {
        // The symmetric-only ChaCha20-Poly1305 fallback is gated on
        // `SecurityLevel::Standard`; higher levels refuse. `CoreConfig::new()`
        // defaults to `SecurityLevel::High`, so the test lowers explicitly.
        let config = CoreConfig::new()
            .with_hardware_acceleration(false)
            .with_security_level(SecurityLevel::Standard);
        let scheme =
            CryptoPolicyEngine::select_encryption_scheme(b"test data", &config, None).unwrap();
        assert_eq!(scheme, CHACHA20_POLY1305);
    }

    #[test]
    fn test_hardware_acceleration_false_high_refuses_silent_pq_strip() {
        let config = CoreConfig::new()
            .with_hardware_acceleration(false)
            .with_security_level(SecurityLevel::High);
        let result = CryptoPolicyEngine::select_encryption_scheme(b"test data", &config, None);
        assert!(matches!(result, Err(TypeError::ConfigurationError(_))));
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("symmetric") || err_msg.contains("ChaCha20"),
            "error must explain the PQ-strip refusal, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_hardware_acceleration_false_maximum_refuses_silent_pq_strip() {
        let config = CoreConfig::new()
            .with_hardware_acceleration(false)
            .with_security_level(SecurityLevel::Maximum);
        let result = CryptoPolicyEngine::select_encryption_scheme(b"test data", &config, None);
        assert!(matches!(result, Err(TypeError::ConfigurationError(_))));
    }

    #[test]
    fn test_hardware_acceleration_true_selects_hybrid_scheme_succeeds() {
        let config = CoreConfig::new()
            .with_hardware_acceleration(true)
            .with_security_level(SecurityLevel::High);
        let scheme =
            CryptoPolicyEngine::select_encryption_scheme(b"test data", &config, None).unwrap();
        // With hw_accel=true, should NOT be chacha20 — parameter changes outcome
        assert_ne!(scheme, CHACHA20_POLY1305);
    }

    #[test]
    fn test_size_conditioned_random_data_speed_high_refuses_silent_downgrade() {
        // Post-85e2bd79e L3 caller-declared `SecurityLevel::High`
        // (ML-KEM-768 / NIST L3) under `(Speed, Random)` MUST refuse rather
        // than silently downgrade to ML-KEM-512 (NIST L1). Previously this
        // returned `Ok(HYBRID_ENCRYPTION_512)` with a `tracing::warn!`,
        // which is observability — not contract enforcement. Now returns
        // `Err(TypeError::ConfigurationError)`. Migration for callers
        // wanting the optimization: pre-set `SecurityLevel::Standard`,
        // or use `select_encryption_scheme_typed` (no downgrade path).
        use crate::primitives::rand::secure_rng;
        use rand::RngCore;
        let mut data = vec![0u8; 8192];
        secure_rng().fill_bytes(&mut data);
        let config = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::High);
        let result = CryptoPolicyEngine::select_encryption_scheme(&data, &config, None);
        assert!(matches!(result, Err(TypeError::ConfigurationError(_))));
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("ML-KEM-768") && err_msg.contains("ML-KEM-512"),
            "error must name both the requested L3 scheme and the rejected L1 downgrade target"
        );
    }

    #[test]
    fn test_size_conditioned_random_data_speed_standard_succeeds() {
        // Companion to `_high_refuses_silent_downgrade`: when caller
        // explicitly declares `Standard`, ML-KEM-512 is the requested
        // level — no refusal, just normal selection.
        use crate::primitives::rand::secure_rng;
        use rand::RngCore;
        let mut data = vec![0u8; 8192];
        secure_rng().fill_bytes(&mut data);
        let config = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::Standard);
        let scheme = CryptoPolicyEngine::select_encryption_scheme(&data, &config, None).unwrap();
        assert_eq!(scheme, HYBRID_ENCRYPTION_512);
    }

    #[test]
    fn test_size_conditioned_structured_data_balanced_no_downgrade_succeeds() {
        let data = b"This is structured text data for encryption testing";
        let config = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Balanced)
            .with_security_level(SecurityLevel::High);
        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None).unwrap();
        // Structured data + Balanced → default for security level, no downgrade
        assert_eq!(scheme, HYBRID_ENCRYPTION_768);
    }

    #[test]
    fn test_force_scheme_returns_forced_scheme_succeeds() {
        use crate::types::CryptoScheme;
        // Symmetric maps to AES-256-GCM (type-safe key dispatch handles hybrid separately)
        let result = CryptoPolicyEngine::force_scheme(&CryptoScheme::Symmetric);
        assert_eq!(result, "aes-256-gcm");

        let result = CryptoPolicyEngine::force_scheme(&CryptoScheme::PostQuantum);
        assert_eq!(result, DEFAULT_PQ_ENCRYPTION_SCHEME);
    }

    // =========================================================================
    // Pattern P4: Parameter Influence Tests
    // Each test proves changing ONLY one field changes the output.
    // =========================================================================

    #[test]
    fn test_security_level_influences_encryption_scheme_succeeds() {
        let data = b"test data for scheme selection";
        let config_a = CoreConfig::new()
            .with_security_level(SecurityLevel::Standard)
            .with_hardware_acceleration(true);
        let result_a = CryptoPolicyEngine::select_encryption_scheme(data, &config_a, None).unwrap();

        let config_b = CoreConfig::new()
            .with_security_level(SecurityLevel::Maximum)
            .with_hardware_acceleration(true);
        let result_b = CryptoPolicyEngine::select_encryption_scheme(data, &config_b, None).unwrap();

        assert_ne!(result_a, result_b, "security_level must influence encryption scheme selection");
    }

    #[test]
    fn test_security_level_influences_signature_scheme_succeeds() {
        let config_a = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let result_a = CryptoPolicyEngine::select_signature_scheme(&config_a).unwrap();

        let config_b = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let result_b = CryptoPolicyEngine::select_signature_scheme(&config_b).unwrap();

        assert_ne!(result_a, result_b, "security_level must influence signature scheme selection");
    }

    #[test]
    fn test_security_level_influences_pq_encryption_scheme_succeeds() {
        let config_a = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let result_a = CryptoPolicyEngine::select_pq_encryption_scheme(&config_a).unwrap();

        let config_b = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let result_b = CryptoPolicyEngine::select_pq_encryption_scheme(&config_b).unwrap();

        assert_ne!(
            result_a, result_b,
            "security_level must influence PQ encryption scheme selection"
        );
    }

    #[test]
    fn test_performance_preference_influences_encryption_scheme_succeeds() {
        use crate::primitives::rand::secure_rng;
        use rand::RngCore;
        // Use random data so the size-conditioned branch activates. Post-L3 audit
        // fix: caller-declared `SecurityLevel::High` + `Speed` + Random
        // data REFUSES (was: silent downgrade to ML-KEM-512). To still
        // prove "performance_preference influences output", compare two
        // shapes: Speed → Err vs Balanced → Ok. The two outputs differ
        // by Result variant, which counts as influence.
        let mut data = vec![0u8; 8192];
        secure_rng().fill_bytes(&mut data);

        let config_a = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::High)
            .with_hardware_acceleration(true);
        let result_a = CryptoPolicyEngine::select_encryption_scheme(&data, &config_a, None);

        let config_b = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Balanced)
            .with_security_level(SecurityLevel::High)
            .with_hardware_acceleration(true);
        let result_b = CryptoPolicyEngine::select_encryption_scheme(&data, &config_b, None);

        // Speed + High + Random must refuse; Balanced + High must succeed.
        // Different Result variants → performance_preference influenced
        // the output.
        assert!(
            matches!(result_a, Err(TypeError::ConfigurationError(_))),
            "Speed + High + Random must refuse silent downgrade"
        );
        assert!(result_b.is_ok(), "Balanced + High must succeed");
        assert_eq!(
            result_b.unwrap(),
            HYBRID_ENCRYPTION_768,
            "Balanced + High must select ML-KEM-768"
        );
    }

    #[test]
    fn test_hardware_acceleration_influences_encryption_scheme_succeeds() {
        // At `SecurityLevel::High`, the `hardware_acceleration = false`
        // branch refuses; the two outputs differ by `Result` variant, which
        // counts as the parameter having influence.
        let data = b"test data for hardware influence";

        let config_a = CoreConfig::new()
            .with_hardware_acceleration(false)
            .with_security_level(SecurityLevel::High);
        let result_a = CryptoPolicyEngine::select_encryption_scheme(data, &config_a, None);

        let config_b = CoreConfig::new()
            .with_hardware_acceleration(true)
            .with_security_level(SecurityLevel::High);
        let result_b = CryptoPolicyEngine::select_encryption_scheme(data, &config_b, None);

        assert!(
            matches!(result_a, Err(TypeError::ConfigurationError(_))),
            "hw_accel = false + High must refuse silent PQ-strip"
        );
        assert!(result_b.is_ok(), "hw_accel = true + High must succeed");
        assert_eq!(
            result_b.unwrap(),
            HYBRID_ENCRYPTION_768,
            "hw_accel = true + High must select ML-KEM-768"
        );
    }

    #[test]
    fn test_fallback_enabled_does_not_influence_scheme_selection_succeeds() {
        // fallback_enabled is consumed by CoreConfig::validate(), not scheme selection.
        // Changing it must NOT change the selected encryption scheme.
        let data = b"test data for fallback influence check";

        let config_a =
            CoreConfig::new().with_security_level(SecurityLevel::High).with_fallback(true);
        let result_a = CryptoPolicyEngine::select_encryption_scheme(data, &config_a, None).unwrap();

        let config_b =
            CoreConfig::new().with_security_level(SecurityLevel::High).with_fallback(false);
        let result_b = CryptoPolicyEngine::select_encryption_scheme(data, &config_b, None).unwrap();

        assert_eq!(
            result_a, result_b,
            "fallback_enabled does not influence scheme selection (consumed by validate() only)"
        );
    }

    #[test]
    fn test_fallback_enabled_influences_validate_returns_error_without_fallback_fails() {
        // fallback_enabled IS consumed by CoreConfig::validate():
        // Speed + !fallback_enabled => error.
        let config_with_fallback = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_fallback(true);
        let config_without_fallback = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_fallback(false);

        assert!(
            config_with_fallback.validate().is_ok(),
            "Speed + fallback_enabled=true must pass validation"
        );
        assert!(
            config_without_fallback.validate().is_err(),
            "Speed + fallback_enabled=false must fail validation"
        );
    }

    #[test]
    fn test_strict_validation_influences_validate_rejects_standard_level_fails() {
        // strict_validation is consumed by CoreConfig::validate():
        // strict=true + Standard security => error; strict=false + Standard => ok.
        let config_strict = CoreConfig::new()
            .with_security_level(SecurityLevel::Standard)
            .with_strict_validation(true);
        let config_relaxed = CoreConfig::new()
            .with_security_level(SecurityLevel::Standard)
            .with_strict_validation(false);

        assert!(
            config_strict.validate().is_err(),
            "strict_validation=true with Standard level must fail validation"
        );
        assert!(
            config_relaxed.validate().is_ok(),
            "strict_validation=false with Standard level must pass validation"
        );
    }

    #[test]
    fn test_strict_validation_does_not_influence_scheme_selection_succeeds() {
        // strict_validation is consumed by validate(), not scheme selection.
        let data = b"test data for strict validation influence check";

        let config_a =
            CoreConfig::new().with_security_level(SecurityLevel::High).with_strict_validation(true);
        let result_a = CryptoPolicyEngine::select_encryption_scheme(data, &config_a, None).unwrap();

        let config_b = CoreConfig::new()
            .with_security_level(SecurityLevel::High)
            .with_strict_validation(false);
        let result_b = CryptoPolicyEngine::select_encryption_scheme(data, &config_b, None).unwrap();

        assert_eq!(
            result_a, result_b,
            "strict_validation does not influence scheme selection (consumed by validate() only)"
        );
    }

    #[test]
    fn test_security_level_influences_pq_signature_scheme_succeeds() {
        let config_a = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let result_a = CryptoPolicyEngine::select_pq_signature_scheme(&config_a).unwrap();

        let config_b = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let result_b = CryptoPolicyEngine::select_pq_signature_scheme(&config_b).unwrap();

        assert_ne!(
            result_a, result_b,
            "security_level must influence PQ signature scheme selection"
        );
    }

    #[test]
    fn test_security_level_influences_encryption_scheme_typed_succeeds() {
        let config_a = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let result_a = CryptoPolicyEngine::select_encryption_scheme_typed(&config_a);

        let config_b = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let result_b = CryptoPolicyEngine::select_encryption_scheme_typed(&config_b);

        assert_ne!(
            result_a, result_b,
            "security_level must influence typed encryption scheme selection"
        );
    }

    // --- select_encryption_scheme_typed_with_mode tests ---

    #[test]
    fn test_selector_pq_only_standard_returns_pq512() {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let scheme = CryptoPolicyEngine::select_encryption_scheme_typed_with_mode(
            &config,
            crate::types::types::CryptoMode::PqOnly,
        );
        assert_eq!(scheme, EncryptionScheme::PqMlKem512Aes256Gcm);
    }

    #[test]
    fn test_selector_pq_only_high_returns_pq768() {
        let config = CoreConfig::new().with_security_level(SecurityLevel::High);
        let scheme = CryptoPolicyEngine::select_encryption_scheme_typed_with_mode(
            &config,
            crate::types::types::CryptoMode::PqOnly,
        );
        assert_eq!(scheme, EncryptionScheme::PqMlKem768Aes256Gcm);
    }

    #[test]
    fn test_selector_pq_only_maximum_returns_pq1024() {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let scheme = CryptoPolicyEngine::select_encryption_scheme_typed_with_mode(
            &config,
            crate::types::types::CryptoMode::PqOnly,
        );
        assert_eq!(scheme, EncryptionScheme::PqMlKem1024Aes256Gcm);
    }

    #[test]
    fn test_selector_hybrid_mode_unchanged_by_refactor() {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let scheme = CryptoPolicyEngine::select_encryption_scheme_typed_with_mode(
            &config,
            crate::types::types::CryptoMode::Hybrid,
        );
        assert_eq!(scheme, EncryptionScheme::HybridMlKem512Aes256Gcm);
    }

    // --- PQ key level mismatch tests ---

    #[test]
    fn test_pq_key_level_mismatch_encrypt_rejected() {
        use crate::hybrid::pq_only::generate_pq_keypair_with_level;
        use crate::primitives::kem::ml_kem::MlKemSecurityLevel;

        let (pk_512, _) = generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem512).unwrap();
        // Scheme expects 768, key is 512
        let result = CryptoPolicyEngine::validate_key_matches_scheme(
            &EncryptKey::PqOnly(&pk_512),
            &EncryptionScheme::PqMlKem768Aes256Gcm,
        );
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("ML-KEM"));
    }

    #[test]
    fn test_pq_key_level_mismatch_decrypt_rejected() {
        use crate::hybrid::pq_only::generate_pq_keypair_with_level;
        use crate::primitives::kem::ml_kem::MlKemSecurityLevel;

        let (_, sk_512) = generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem512).unwrap();
        let result = CryptoPolicyEngine::validate_decrypt_key_matches_scheme(
            &DecryptKey::PqOnly(&sk_512),
            &EncryptionScheme::PqMlKem1024Aes256Gcm,
        );
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("ML-KEM"));
    }

    #[test]
    fn test_hardware_acceleration_does_not_influence_signature_scheme_succeeds() {
        // select_signature_scheme is driven only by security_level; hardware_acceleration
        // is not consulted for signature scheme selection.
        let config_a = CoreConfig::new()
            .with_security_level(SecurityLevel::High)
            .with_hardware_acceleration(false);
        let result_a = CryptoPolicyEngine::select_signature_scheme(&config_a).unwrap();

        let config_b = CoreConfig::new()
            .with_security_level(SecurityLevel::High)
            .with_hardware_acceleration(true);
        let result_b = CryptoPolicyEngine::select_signature_scheme(&config_b).unwrap();

        assert_eq!(
            result_a, result_b,
            "hardware_acceleration must NOT influence signature scheme selection"
        );
    }

    #[test]
    fn test_performance_preference_influences_adaptive_selection_succeeds() {
        // adaptive_selection uses performance_preference to choose between
        // schemes when performance metrics cross thresholds. Post-L3
        // caller-declared High + Speed + Repetitive +
        // slow-encryption now REFUSES (was: silent downgrade to L1).
        // We still prove influence by comparing Result variants:
        // Speed → Err, Memory → Ok (memory branch passes through to
        // the L3-preserving select_encryption_scheme path).
        // 4096 bytes of 'A': hits ML_KEM_DOWNGRADE_REFUSAL_THRESHOLD
        // boundary so the Memory branch in select_encryption_scheme
        // does NOT refuse (only refuses for data.len() < 4096).
        // Chunking divides evenly into 8-byte blocks → detected as
        // Repetitive. Previous 52-byte and 64-byte literals were
        // either misdetected (chunk-size mismatch) or triggered the
        // Memory refusal — both broke this test under the L3 fix.
        let data = vec![b'A'; ML_KEM_DOWNGRADE_REFUSAL_THRESHOLD];
        let data = data.as_slice();

        let config_speed = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::High);

        let config_memory = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Memory)
            .with_security_level(SecurityLevel::High);

        // High encryption_speed_ms (>1000ms) + repetitive data activates
        // the Speed branch — which now refuses the L3→L1 silent downgrade.
        let metrics_slow = PerformanceMetrics { encryption_speed_ms: 1500.0, memory_usage_mb: 0.0 };

        let result_speed =
            CryptoPolicyEngine::adaptive_selection(data, &metrics_slow, &config_speed);
        let result_memory =
            CryptoPolicyEngine::adaptive_selection(data, &metrics_slow, &config_memory);

        assert!(
            matches!(result_speed, Err(TypeError::ConfigurationError(_))),
            "Speed + High + Repetitive + slow encryption must refuse silent downgrade"
        );
        assert!(
            result_memory.is_ok(),
            "Memory + High passes through select_encryption_scheme \
             (no Memory-pressure metric tripped); should succeed"
        );
    }
}
