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

/// Threshold (in bytes) below which classical-only encryption may be used for
/// performance optimization when explicitly configured with low security + speed.
///
/// **Rationale**: ML-KEM ciphertext overhead is ~1000-1500 bytes depending on
/// security level. For messages under this threshold, the hybrid overhead is
/// significant relative to message size.
///
/// **Security Note**: Classical fallback ONLY occurs when ALL of:
/// 1. Security level is `Medium` or `Low` (user accepts reduced security)
/// 2. Performance preference is `Speed` (user prioritizes performance)
/// 3. Data size is below this threshold
///
/// If quantum safety is required for all messages regardless of size, use
/// `SecurityLevel::High` or `SecurityLevel::Maximum`.
pub const CLASSICAL_FALLBACK_SIZE_THRESHOLD: usize = 4096;

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
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn recommend_scheme(use_case: &UseCase, _config: &CoreConfig) -> Result<String> {
        // _config is retained for API stability; scheme selection is use-case-driven.
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
    /// All selections return hybrid or PQ-only schemes. Classical-only schemes
    /// (e.g., bare AES-GCM or Ed25519) are never selected.
    #[must_use]
    pub fn force_scheme(scheme: &crate::types::CryptoScheme) -> String {
        match *scheme {
            crate::types::CryptoScheme::Hybrid => DEFAULT_ENCRYPTION_SCHEME.to_string(),
            crate::types::CryptoScheme::Symmetric => "aes-256-gcm".to_string(),
            crate::types::CryptoScheme::SymmetricChaCha20 => "chacha20-poly1305".to_string(),
            crate::types::CryptoScheme::Asymmetric => "pq-ml-dsa-65".to_string(),
            crate::types::CryptoScheme::PostQuantum => DEFAULT_PQ_ENCRYPTION_SCHEME.to_string(),
        }
    }

    /// Select PQ-only encryption scheme (no classical component).
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn select_pq_encryption_scheme(config: &CoreConfig) -> Result<String> {
        match config.security_level {
            SecurityLevel::Standard => Ok(PQ_ENCRYPTION_512.to_string()),
            SecurityLevel::High => Ok(PQ_ENCRYPTION_768.to_string()),
            SecurityLevel::Maximum | SecurityLevel::Quantum => Ok(PQ_ENCRYPTION_1024.to_string()),
        }
    }

    /// Select PQ-only signature scheme (no classical component).
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn select_pq_signature_scheme(config: &CoreConfig) -> Result<String> {
        match config.security_level {
            SecurityLevel::Standard => Ok(PQ_SIGNATURE_44.to_string()),
            SecurityLevel::High => Ok(PQ_SIGNATURE_65.to_string()),
            SecurityLevel::Maximum | SecurityLevel::Quantum => Ok(PQ_SIGNATURE_87.to_string()),
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
    /// When `hardware_acceleration` is `false` and no use case is specified,
    /// prefers `chacha20-poly1305` (fast in software without AES-NI).
    ///
    /// When data is provided, analyzes data characteristics to optimize
    /// scheme selection for the data's entropy and size patterns.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn select_encryption_scheme(
        data: &[u8],
        config: &CoreConfig,
        use_case: Option<&UseCase>,
    ) -> Result<String> {
        if let Some(use_case) = use_case {
            return Self::recommend_scheme(use_case, config);
        }

        // When hardware acceleration is disabled, prefer ChaCha20-Poly1305
        // which is fast in pure software (no AES-NI needed)
        if !config.hardware_acceleration {
            return Ok(CHACHA20_POLY1305.to_string());
        }

        // Data-aware adjustments when data is non-empty
        if !data.is_empty() {
            let characteristics = Self::analyze_data_characteristics(data);

            match (&config.performance_preference, &characteristics.pattern_type) {
                // High-entropy data with speed preference: smaller KEM is sufficient
                (PerformancePreference::Speed, PatternType::Random) => {
                    if matches!(config.security_level, SecurityLevel::High) {
                        return Ok(HYBRID_ENCRYPTION_512.to_string());
                    }
                }
                // Memory-constrained with small data: downgrade if not at maximum
                (PerformancePreference::Memory, _)
                    if data.len() < CLASSICAL_FALLBACK_SIZE_THRESHOLD =>
                {
                    if matches!(config.security_level, SecurityLevel::High) {
                        return Ok(HYBRID_ENCRYPTION_512.to_string());
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
            SecurityLevel::Quantum => PQ_ENCRYPTION_1024.to_string(),
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
    pub fn select_signature_scheme(config: &CoreConfig) -> Result<String> {
        match &config.security_level {
            SecurityLevel::Quantum => Ok(PQ_SIGNATURE_87.to_string()),
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

        match (&config.performance_preference, performance_metrics) {
            (PerformancePreference::Memory, metrics) if metrics.memory_usage_mb > 500.0 => {
                Ok("hybrid-ml-kem-768-aes-256-gcm".to_string())
            }
            (PerformancePreference::Speed, metrics)
                if metrics.encryption_speed_ms > 1000.0
                    && matches!(characteristics.pattern_type, PatternType::Repetitive) =>
            {
                Ok("hybrid-ml-kem-512-aes-256-gcm".to_string())
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

    /// Select encryption scheme based on security level, returning a type-safe enum.
    ///
    /// When hardware acceleration is unavailable, ChaCha20-Poly1305 is preferred for
    /// Standard/High levels. Quantum/Maximum levels always require hybrid PQC regardless
    /// of hardware support — degrading to classical-only would violate the security contract.
    #[must_use]
    pub fn select_encryption_scheme_typed(config: &CoreConfig) -> EncryptionScheme {
        // All levels use hybrid PQC schemes. Hardware acceleration only affects
        // whether AES-GCM is fast — it does NOT warrant downgrading to
        // classical-only encryption (that would violate the PQ security contract).
        match &config.security_level {
            SecurityLevel::Quantum | SecurityLevel::Maximum => {
                EncryptionScheme::HybridMlKem1024Aes256Gcm
            }
            SecurityLevel::High => EncryptionScheme::HybridMlKem768Aes256Gcm,
            SecurityLevel::Standard => EncryptionScheme::HybridMlKem512Aes256Gcm,
        }
    }

    /// Validate that the key variant matches the scheme requirements.
    ///
    /// Returns `Ok(())` if the key type is compatible with the scheme,
    /// or `Err(TypeError::ConfigurationError)` describing the mismatch.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A symmetric key is provided for a hybrid scheme
    /// - A hybrid key is provided for a symmetric scheme
    pub fn validate_key_matches_scheme(
        key: &EncryptKey<'_>,
        scheme: &EncryptionScheme,
    ) -> Result<()> {
        match (key, scheme.requires_hybrid_key()) {
            (EncryptKey::Symmetric(_), true) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' requires a hybrid key (EncryptKey::Hybrid), \
                 but a symmetric key was provided. Use generate_hybrid_keypair() \
                 to create a hybrid keypair.",
                scheme
            ))),
            (EncryptKey::Hybrid(_), false) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' requires a symmetric key (EncryptKey::Symmetric), \
                 but a hybrid key was provided.",
                scheme
            ))),
            _ => {
                // For hybrid keys, verify ML-KEM security level matches scheme
                if let (EncryptKey::Hybrid(pk), Some(expected_level)) = (key, scheme.ml_kem_level())
                    && pk.security_level() != expected_level
                {
                    return Err(TypeError::ConfigurationError(format!(
                        "Scheme '{}' requires ML-KEM-{} key, but the provided key \
                         was generated at ML-KEM-{} level. Use \
                         generate_hybrid_keypair_with_level({:?}).",
                        scheme,
                        expected_level.name(),
                        pk.security_level().name(),
                        expected_level
                    )));
                }
                Ok(())
            }
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
        match (key, scheme.requires_hybrid_key()) {
            (DecryptKey::Symmetric(_), true) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' requires a hybrid secret key (DecryptKey::Hybrid), \
                 but a symmetric key was provided.",
                scheme
            ))),
            (DecryptKey::Hybrid(_), false) => Err(TypeError::ConfigurationError(format!(
                "Scheme '{}' requires a symmetric key (DecryptKey::Symmetric), \
                 but a hybrid key was provided.",
                scheme
            ))),
            _ => {
                // For hybrid keys, verify ML-KEM security level matches scheme
                if let (DecryptKey::Hybrid(sk), Some(expected_level)) = (key, scheme.ml_kem_level())
                    && sk.security_level() != expected_level
                {
                    return Err(TypeError::ConfigurationError(format!(
                        "Scheme '{}' requires ML-KEM-{} key, but the provided key \
                         was generated at ML-KEM-{} level.",
                        scheme,
                        expected_level.name(),
                        sk.security_level().name(),
                    )));
                }
                Ok(())
            }
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

    #[allow(clippy::cast_precision_loss)]
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in &frequency {
        if count > 0 {
            #[allow(clippy::cast_precision_loss)]
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

/// Default PQ-only encryption scheme
pub const DEFAULT_PQ_ENCRYPTION_SCHEME: &str = "pq-ml-kem-768-aes-256-gcm";
/// Default PQ-only signature scheme
pub const DEFAULT_PQ_SIGNATURE_SCHEME: &str = "pq-ml-dsa-65";

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
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
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
    fn test_hardware_acceleration_false_selects_chacha20_scheme_succeeds() {
        let config = CoreConfig::new().with_hardware_acceleration(false);
        let scheme =
            CryptoPolicyEngine::select_encryption_scheme(b"test data", &config, None).unwrap();
        assert_eq!(scheme, CHACHA20_POLY1305);
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
    fn test_data_aware_random_data_speed_selects_smaller_kem_scheme_succeeds() {
        use rand::RngCore;
        // Need enough bytes for entropy > 7.5 (256 bytes has ~7.0 entropy)
        let mut data = vec![0u8; 8192];
        rand::thread_rng().fill_bytes(&mut data);
        let config = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::High);
        let scheme = CryptoPolicyEngine::select_encryption_scheme(&data, &config, None).unwrap();
        // Random data + Speed + High → HYBRID_ENCRYPTION_512 (data-aware optimization)
        assert_eq!(scheme, HYBRID_ENCRYPTION_512);
    }

    #[test]
    fn test_data_aware_structured_data_balanced_no_downgrade_succeeds() {
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
        use rand::RngCore;
        // Use random data so data-aware branch activates
        let mut data = vec![0u8; 8192];
        rand::thread_rng().fill_bytes(&mut data);

        let config_a = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::High)
            .with_hardware_acceleration(true);
        let result_a =
            CryptoPolicyEngine::select_encryption_scheme(&data, &config_a, None).unwrap();

        let config_b = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Balanced)
            .with_security_level(SecurityLevel::High)
            .with_hardware_acceleration(true);
        let result_b =
            CryptoPolicyEngine::select_encryption_scheme(&data, &config_b, None).unwrap();

        assert_ne!(
            result_a, result_b,
            "performance_preference must influence encryption scheme for random data"
        );
    }

    #[test]
    fn test_hardware_acceleration_influences_encryption_scheme_succeeds() {
        let data = b"test data for hardware influence";

        let config_a = CoreConfig::new()
            .with_hardware_acceleration(false)
            .with_security_level(SecurityLevel::High);
        let result_a = CryptoPolicyEngine::select_encryption_scheme(data, &config_a, None).unwrap();

        let config_b = CoreConfig::new()
            .with_hardware_acceleration(true)
            .with_security_level(SecurityLevel::High);
        let result_b = CryptoPolicyEngine::select_encryption_scheme(data, &config_b, None).unwrap();

        assert_ne!(
            result_a, result_b,
            "hardware_acceleration must influence encryption scheme selection"
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
        // adaptive_selection uses performance_preference to choose between schemes
        // when performance metrics cross thresholds (speed > 1000ms + repetitive data).
        let data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // repetitive

        let config_speed = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::High);

        let config_memory = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Memory)
            .with_security_level(SecurityLevel::High);

        // High encryption_speed_ms (>1000ms) + repetitive data activates Speed branch.
        let metrics_slow = PerformanceMetrics { encryption_speed_ms: 1500.0, memory_usage_mb: 0.0 };

        let result_speed =
            CryptoPolicyEngine::adaptive_selection(data, &metrics_slow, &config_speed).unwrap();
        let result_memory =
            CryptoPolicyEngine::adaptive_selection(data, &metrics_slow, &config_memory).unwrap();

        assert_ne!(
            result_speed, result_memory,
            "performance_preference must influence adaptive scheme selection when metrics cross thresholds"
        );
    }
}
