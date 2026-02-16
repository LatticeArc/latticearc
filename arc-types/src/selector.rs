//! Cryptographic Policy Engine
//!
//! Provides intelligent policy-based selection of encryption and signature schemes
//! based on data characteristics, security requirements, and performance preferences.
//! All logic is pure Rust with zero FFI dependencies.

use crate::{
    config::CoreConfig,
    error::{Result, TypeError},
    traits::{DataCharacteristics, PatternType, SchemeSelector},
    types::{CryptoContext, PerformancePreference, SecurityLevel, UseCase},
};

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
    pub fn recommend_scheme(use_case: &UseCase, config: &CoreConfig) -> Result<String> {
        let use_case_clone = use_case.clone();
        let _ctx = CryptoContext {
            security_level: config.security_level.clone(),
            performance_preference: config.performance_preference.clone(),
            use_case: Some(use_case_clone),
            hardware_acceleration: config.hardware_acceleration,
            timestamp: chrono::Utc::now(),
        };

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

            // Advanced
            UseCase::SearchableEncryption => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::HomomorphicComputation => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
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
            crate::types::CryptoScheme::Symmetric => "hybrid-ml-kem-768-aes-256-gcm".to_string(),
            crate::types::CryptoScheme::Asymmetric => "pq-ml-dsa-65".to_string(),
            crate::types::CryptoScheme::Homomorphic => "hybrid-ml-kem-768-aes-256-gcm".to_string(),
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
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn select_encryption_scheme(
        _data: &[u8],
        config: &CoreConfig,
        use_case: Option<&UseCase>,
    ) -> Result<String> {
        if let Some(use_case) = use_case {
            return Self::recommend_scheme(use_case, config);
        }

        match &config.security_level {
            SecurityLevel::Quantum => Ok(PQ_ENCRYPTION_1024.to_string()),
            SecurityLevel::Maximum => Ok(HYBRID_ENCRYPTION_1024.to_string()),
            SecurityLevel::High => Ok(HYBRID_ENCRYPTION_768.to_string()),
            SecurityLevel::Standard => Ok(HYBRID_ENCRYPTION_512.to_string()),
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

    /// Context-aware scheme selection based on data characteristics and configuration.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn select_for_context(_data: &[u8], config: &CoreConfig) -> Result<String> {
        match &config.security_level {
            SecurityLevel::Quantum => Ok(PQ_ENCRYPTION_1024.to_string()),
            SecurityLevel::Maximum => Ok(HYBRID_ENCRYPTION_1024.to_string()),
            SecurityLevel::High => Ok(HYBRID_ENCRYPTION_768.to_string()),
            SecurityLevel::Standard => Ok(HYBRID_ENCRYPTION_512.to_string()),
        }
    }

    /// Adaptive selection based on runtime performance metrics.
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
        let base_scheme = Self::select_for_context(data, config)?;

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
                security_level: ctx.security_level.clone(),
                performance_preference: ctx.performance_preference.clone(),
                hardware_acceleration: ctx.hardware_acceleration,
                fallback_enabled: true,
                strict_validation: true,
            },
            ctx.use_case.as_ref(),
        )
    }

    fn select_signature_scheme(
        &self,
        ctx: &CryptoContext,
    ) -> std::result::Result<String, Self::Error> {
        Self::select_signature_scheme(&CoreConfig {
            security_level: ctx.security_level.clone(),
            performance_preference: ctx.performance_preference.clone(),
            hardware_acceleration: ctx.hardware_acceleration,
            fallback_enabled: true,
            strict_validation: true,
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

/// Classical symmetric encryption scheme identifier (decrypt compatibility only)
pub const CLASSICAL_AES_GCM: &str = "aes-256-gcm";
/// Classical signature scheme identifier (decrypt compatibility only)
pub const CLASSICAL_ED25519: &str = "ed25519";

/// Runtime performance metrics for adaptive scheme selection.
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Average encryption time in milliseconds.
    pub encryption_speed_ms: f64,
    /// Average decryption time in milliseconds.
    pub decryption_speed_ms: f64,
    /// Current memory usage in megabytes.
    pub memory_usage_mb: f64,
    /// Current CPU usage percentage.
    pub cpu_usage_percent: f64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            encryption_speed_ms: 100.0,
            decryption_speed_ms: 50.0,
            memory_usage_mb: 100.0,
            cpu_usage_percent: 25.0,
        }
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
    fn test_scheme_constants() {
        assert_eq!(DEFAULT_ENCRYPTION_SCHEME, "hybrid-ml-kem-768-aes-256-gcm");
        assert_eq!(DEFAULT_SIGNATURE_SCHEME, "hybrid-ml-dsa-65-ed25519");
    }

    #[test]
    fn test_policy_engine_new() {
        let engine = CryptoPolicyEngine::new();
        assert!(std::mem::size_of_val(&engine) == 0);
    }

    #[test]
    fn test_default_scheme() {
        assert_eq!(CryptoPolicyEngine::default_scheme(), DEFAULT_ENCRYPTION_SCHEME);
    }

    #[test]
    fn test_recommend_scheme_secure_messaging() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-768-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_encryption_scheme_maximum_security() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let data = b"test data";
        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
        assert_eq!(scheme, "hybrid-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_analyze_empty_data() {
        let data: &[u8] = &[];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.size, 0);
        assert_eq!(characteristics.entropy, 0.0);
    }

    #[test]
    fn test_analyze_repetitive_data() {
        let data = vec![0u8; 1000];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert!(characteristics.entropy < 1.0);
        assert_eq!(characteristics.pattern_type, PatternType::Repetitive);
    }
}
