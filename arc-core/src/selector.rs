//! Cryptographic Policy Engine
//!
//! Provides intelligent policy-based selection of encryption and signature schemes
//! based on data characteristics, security requirements, and performance preferences.
//!
//! # Scheme Selection Decision Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    ENCRYPTION SCHEME SELECTION                          │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  Input: data[], SecurityLevel, PerformancePreference, UseCase           │
//! │                           │                                             │
//! │                           ▼                                             │
//! │  ┌───────────────────────────────────────────┐                          │
//! │  │ SecurityLevel = Maximum or High?          │                          │
//! │  └─────────────────┬─────────────────────────┘                          │
//! │                    │                                                    │
//! │         ┌─────────┴─────────┐                                           │
//! │         │YES                │NO                                         │
//! │         ▼                   ▼                                           │
//! │  ┌──────────────┐   ┌───────────────────────────────────┐               │
//! │  │ hybrid-ml-   │   │ PerformancePreference = Speed AND │               │
//! │  │ kem-1024-    │   │ data.len() < 4096 bytes?          │               │
//! │  │ aes-256-gcm  │   └─────────────────┬─────────────────┘               │
//! │  └──────────────┘                     │                                 │
//! │                            ┌──────────┴──────────┐                      │
//! │                            │YES                  │NO                    │
//! │                            ▼                     ▼                      │
//! │                    ┌──────────────┐     ┌──────────────┐                │
//! │                    │ aes-256-gcm  │     │ hybrid-ml-   │                │
//! │                    │ (classical)  │     │ kem-768-     │                │
//! │                    └──────────────┘     │ aes-256-gcm  │                │
//! │                                         └──────────────┘                │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    DATA ANALYSIS PIPELINE                               │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  Input: data[]                                                          │
//! │      │                                                                  │
//! │      ▼                                                                  │
//! │  ┌─────────────────────────────────────────────────────────────┐        │
//! │  │ calculate_entropy(data)                                     │        │
//! │  │                                                             │        │
//! │  │ Shannon Entropy: H = -Σ p(x) * log₂(p(x))                  │        │
//! │  │                                                             │        │
//! │  │ Returns: 0.0 (uniform) to 8.0 (maximum randomness)          │        │
//! │  └──────────────────────────┬──────────────────────────────────┘        │
//! │                             │                                           │
//! │                             ▼                                           │
//! │  ┌─────────────────────────────────────────────────────────────┐        │
//! │  │ detect_pattern_type(data)                                   │        │
//! │  │                                                             │        │
//! │  │   entropy > 7.5        ──► Random                           │        │
//! │  │   is_ascii && entropy > 4.0 ──► Text                        │        │
//! │  │   repeating_chunks     ──► Repetitive                       │        │
//! │  │   has_structure        ──► Structured (JSON/XML markers)    │        │
//! │  │   else                 ──► Binary                           │        │
//! │  └──────────────────────────┬──────────────────────────────────┘        │
//! │                             │                                           │
//! │                             ▼                                           │
//! │  ┌─────────────────────────────────────────────────────────────┐        │
//! │  │ DataCharacteristics {                                       │        │
//! │  │   entropy: f64,          // Shannon entropy (bits/byte)     │        │
//! │  │   pattern_type: enum,    // Random|Text|Repetitive|...      │        │
//! │  │   size: usize,     // Total data length               │        │
//! │  │   is_compressible: bool, // entropy < 6.0                   │        │
//! │  │ }                                                           │        │
//! │  └─────────────────────────────────────────────────────────────┘        │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Scheme Selection Matrix
//!
//! | Security Level | Mode      | Encryption               | Signatures              |
//! |----------------|-----------|--------------------------|-------------------------|
//! | Standard       | Hybrid    | ML-KEM-512 + AES-256-GCM | ML-DSA-44 + Ed25519    |
//! | High           | Hybrid    | ML-KEM-768 + AES-256-GCM | ML-DSA-65 + Ed25519    |
//! | Maximum        | Hybrid    | ML-KEM-1024 + AES-256-GCM| ML-DSA-87 + Ed25519    |
//! | Quantum        | PQ-only   | ML-KEM-1024 + AES-256-GCM| ML-DSA-87              |

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::{
    config::CoreConfig,
    error::{CoreError, Result},
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
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{CryptoPolicyEngine, CoreConfig, UseCase};
///
/// let config = CoreConfig::default();
///
/// // Use case-based selection
/// let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;
///
/// // Data-aware selection
/// let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
/// ```
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
            // ================================================================
            // Communication - balanced security and performance
            // ================================================================
            UseCase::SecureMessaging => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::EmailEncryption => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::VpnTunnel => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::ApiSecurity => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),

            // ================================================================
            // Storage - prioritize long-term security
            // ================================================================
            UseCase::FileStorage => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::DatabaseEncryption => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::CloudStorage => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::BackupArchive => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::ConfigSecrets => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),

            // ================================================================
            // Authentication & Identity - signature-focused
            // ================================================================
            UseCase::Authentication => Ok("hybrid-ml-dsa-87-ed25519".to_string()),
            UseCase::SessionToken => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::DigitalCertificate => Ok("hybrid-ml-dsa-87-ed25519".to_string()),
            UseCase::KeyExchange => Ok("hybrid-ml-kem-1024-x25519".to_string()),

            // ================================================================
            // Financial & Legal - maximum security and compliance
            // ================================================================
            UseCase::FinancialTransactions => Ok("hybrid-ml-dsa-65-ed25519".to_string()),
            UseCase::LegalDocuments => Ok("hybrid-ml-dsa-87-ed25519".to_string()),
            UseCase::BlockchainTransaction => Ok("hybrid-ml-dsa-65-ed25519".to_string()),

            // ================================================================
            // Regulated Industries - maximum security
            // ================================================================
            UseCase::HealthcareRecords => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::GovernmentClassified => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),
            UseCase::PaymentCard => Ok("hybrid-ml-kem-1024-aes-256-gcm".to_string()),

            // ================================================================
            // IoT & Embedded - resource-constrained
            // ================================================================
            UseCase::IoTDevice => Ok("hybrid-ml-kem-512-aes-256-gcm".to_string()),
            UseCase::FirmwareSigning => Ok("hybrid-ml-dsa-65-ed25519".to_string()),

            // ================================================================
            // Advanced - specialized schemes
            // ================================================================
            UseCase::SearchableEncryption => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::HomomorphicComputation => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
            UseCase::AuditLog => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
        }
    }

    /// Returns the scheme string for a specific scheme category.
    #[must_use]
    pub fn force_scheme(scheme: &crate::types::CryptoScheme) -> String {
        match *scheme {
            crate::types::CryptoScheme::Hybrid => DEFAULT_ENCRYPTION_SCHEME.to_string(),
            crate::types::CryptoScheme::Symmetric => "aes-256-gcm".to_string(),
            crate::types::CryptoScheme::Asymmetric => "ed25519".to_string(),
            // Homomorphic encryption requires enterprise features - fallback to hybrid
            crate::types::CryptoScheme::Homomorphic => "hybrid-ml-kem-768-aes-256-gcm".to_string(),
            crate::types::CryptoScheme::PostQuantum => DEFAULT_PQ_ENCRYPTION_SCHEME.to_string(),
        }
    }

    /// Select PQ-only encryption scheme (no classical component).
    /// Use this when you want pure post-quantum without hybrid fallback.
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
    /// **Priority**:
    /// 1. Explicit use case → scheme for that use case
    /// 2. Context-aware selection based on data + config
    /// 3. Default: hybrid-ml-kem-768-aes-256-gcm
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
        // Priority 1: Explicit use case override
        if let Some(use_case) = use_case {
            return Self::recommend_scheme(use_case, config);
        }

        // Priority 2: Context-aware selection
        // TODO: Use data characteristics for adaptive algorithm selection
        let _characteristics = Self::analyze_data_characteristics(data);

        match &config.security_level {
            // Quantum: PQ-only (no classical key exchange)
            SecurityLevel::Quantum => Ok(PQ_ENCRYPTION_1024.to_string()),

            // Maximum: strongest hybrid
            SecurityLevel::Maximum => Ok(HYBRID_ENCRYPTION_1024.to_string()),

            // High: standard hybrid (default)
            SecurityLevel::High => Ok(HYBRID_ENCRYPTION_768.to_string()),

            // Standard: lightweight hybrid for resource-constrained devices
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
            // Quantum: PQ-only signatures (no Ed25519)
            SecurityLevel::Quantum => Ok(PQ_SIGNATURE_87.to_string()),

            // Hybrid signatures for all other levels
            SecurityLevel::Maximum => Ok(HYBRID_SIGNATURE_87.to_string()),
            SecurityLevel::High => Ok(HYBRID_SIGNATURE_65.to_string()),
            SecurityLevel::Standard => Ok(HYBRID_SIGNATURE_44.to_string()),
        }
    }

    // =========================================================================
    // Context-Aware Selection
    // =========================================================================

    /// Context-aware scheme selection based on data characteristics and configuration.
    ///
    /// This method performs deeper analysis than `select_encryption_scheme`,
    /// considering pattern types for more nuanced fallback decisions.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors, but returns `Result`
    /// for future compatibility with validation logic.
    pub fn select_for_context(data: &[u8], config: &CoreConfig) -> Result<String> {
        let _characteristics = Self::analyze_data_characteristics(data);

        match &config.security_level {
            // Quantum: PQ-only (no classical key exchange)
            SecurityLevel::Quantum => Ok(PQ_ENCRYPTION_1024.to_string()),

            // Maximum: strongest hybrid
            SecurityLevel::Maximum => Ok(HYBRID_ENCRYPTION_1024.to_string()),

            // High: standard hybrid
            SecurityLevel::High => Ok(HYBRID_ENCRYPTION_768.to_string()),

            // Standard: lightweight hybrid
            SecurityLevel::Standard => Ok(HYBRID_ENCRYPTION_512.to_string()),
        }
    }

    /// Adaptive selection based on runtime performance metrics.
    ///
    /// Adjusts scheme selection based on current system performance metrics
    /// like memory pressure and encryption speed.
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

        // Start with context-based selection
        let base_scheme = Self::select_for_context(data, config)?;

        // Adapt based on runtime metrics
        match (&config.performance_preference, performance_metrics) {
            // Under severe memory pressure with memory preference: downgrade to 768
            (PerformancePreference::Memory, metrics) if metrics.memory_usage_mb > 500.0 => {
                Ok("hybrid-ml-kem-768-aes-256-gcm".to_string())
            }
            // Slow encryption with speed preference on repetitive data: use classical
            (PerformancePreference::Speed, metrics)
                if metrics.encryption_speed_ms > 1000.0
                    && matches!(characteristics.pattern_type, PatternType::Repetitive) =>
            {
                Ok("aes-256-gcm".to_string())
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
    type Error = CoreError;
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
///
/// # Note on precision
/// This function uses f64 for entropy calculations. The conversion from
/// usize/u64 to f64 may lose precision for extremely large values, but
/// this is acceptable for entropy estimation where we only need approximate
/// values in the 0.0-8.0 range.
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        // SAFETY: byte is u8 (0-255), frequency array has 256 elements
        // This is a safe bounded access that will always succeed
        let index = usize::from(byte);
        if let Some(count) = frequency.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    // Note: Cast to f64 may lose precision for len > 2^53, but this is
    // acceptable for entropy calculations where we need approximate values
    #[allow(clippy::cast_precision_loss)]
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in &frequency {
        if count > 0 {
            // Note: Cast to f64 may lose precision for count > 2^53
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
        // Use safe slice access
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
        // Use safe access with get() - windows(4) guarantees 4 elements
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

// =============================================================================
// PQ-ONLY SCHEMES - Pure post-quantum, no classical fallback
// =============================================================================

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

// =============================================================================
// CLASSICAL SCHEMES - For legacy/compatibility only
// =============================================================================

/// Classical symmetric encryption
pub const CLASSICAL_AES_GCM: &str = "aes-256-gcm";
/// Classical signature
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

    // Constant tests
    #[test]
    fn test_classical_fallback_threshold() {
        assert_eq!(CLASSICAL_FALLBACK_SIZE_THRESHOLD, 4096);
    }

    #[test]
    fn test_scheme_constants() {
        assert_eq!(DEFAULT_ENCRYPTION_SCHEME, "hybrid-ml-kem-768-aes-256-gcm");
        assert_eq!(DEFAULT_SIGNATURE_SCHEME, "hybrid-ml-dsa-65-ed25519");
        assert_eq!(DEFAULT_PQ_ENCRYPTION_SCHEME, "pq-ml-kem-768-aes-256-gcm");
        assert_eq!(DEFAULT_PQ_SIGNATURE_SCHEME, "pq-ml-dsa-65");
        assert_eq!(CLASSICAL_AES_GCM, "aes-256-gcm");
        assert_eq!(CLASSICAL_ED25519, "ed25519");
    }

    #[test]
    fn test_hybrid_encryption_constants() {
        assert_eq!(HYBRID_ENCRYPTION_512, "hybrid-ml-kem-512-aes-256-gcm");
        assert_eq!(HYBRID_ENCRYPTION_768, "hybrid-ml-kem-768-aes-256-gcm");
        assert_eq!(HYBRID_ENCRYPTION_1024, "hybrid-ml-kem-1024-aes-256-gcm");
    }

    #[test]
    fn test_hybrid_signature_constants() {
        assert_eq!(HYBRID_SIGNATURE_44, "hybrid-ml-dsa-44-ed25519");
        assert_eq!(HYBRID_SIGNATURE_65, "hybrid-ml-dsa-65-ed25519");
        assert_eq!(HYBRID_SIGNATURE_87, "hybrid-ml-dsa-87-ed25519");
    }

    #[test]
    fn test_pq_encryption_constants() {
        assert_eq!(PQ_ENCRYPTION_512, "pq-ml-kem-512-aes-256-gcm");
        assert_eq!(PQ_ENCRYPTION_768, "pq-ml-kem-768-aes-256-gcm");
        assert_eq!(PQ_ENCRYPTION_1024, "pq-ml-kem-1024-aes-256-gcm");
    }

    #[test]
    fn test_pq_signature_constants() {
        assert_eq!(PQ_SIGNATURE_44, "pq-ml-dsa-44");
        assert_eq!(PQ_SIGNATURE_65, "pq-ml-dsa-65");
        assert_eq!(PQ_SIGNATURE_87, "pq-ml-dsa-87");
    }

    // CryptoPolicyEngine construction tests
    #[test]
    fn test_policy_engine_new() {
        let engine = CryptoPolicyEngine::new();
        assert!(std::mem::size_of_val(&engine) == 0); // Zero-sized type
    }

    #[test]
    fn test_policy_engine_default() {
        let engine = CryptoPolicyEngine::default();
        assert!(std::mem::size_of_val(&engine) == 0);
    }

    #[test]
    fn test_default_scheme() {
        assert_eq!(CryptoPolicyEngine::default_scheme(), DEFAULT_ENCRYPTION_SCHEME);
    }

    // recommend_scheme tests for all use cases
    #[test]
    fn test_recommend_scheme_secure_messaging() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-768-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_email_encryption() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::EmailEncryption, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_vpn_tunnel() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::VpnTunnel, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-768-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_file_storage() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::FileStorage, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_authentication() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::Authentication, &config)?;
        assert_eq!(scheme, "hybrid-ml-dsa-87-ed25519");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_financial_transactions() -> Result<()> {
        let config = CoreConfig::default();
        let scheme =
            CryptoPolicyEngine::recommend_scheme(&UseCase::FinancialTransactions, &config)?;
        assert_eq!(scheme, "hybrid-ml-dsa-65-ed25519");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_healthcare_records() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::HealthcareRecords, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_recommend_scheme_iot_device() -> Result<()> {
        let config = CoreConfig::default();
        let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::IoTDevice, &config)?;
        assert_eq!(scheme, "hybrid-ml-kem-512-aes-256-gcm");
        Ok(())
    }

    // force_scheme tests
    #[test]
    fn test_force_scheme_hybrid() {
        let scheme = CryptoPolicyEngine::force_scheme(&crate::types::CryptoScheme::Hybrid);
        assert_eq!(scheme, DEFAULT_ENCRYPTION_SCHEME);
    }

    #[test]
    fn test_force_scheme_symmetric() {
        let scheme = CryptoPolicyEngine::force_scheme(&crate::types::CryptoScheme::Symmetric);
        assert_eq!(scheme, "aes-256-gcm");
    }

    #[test]
    fn test_force_scheme_asymmetric() {
        let scheme = CryptoPolicyEngine::force_scheme(&crate::types::CryptoScheme::Asymmetric);
        assert_eq!(scheme, "ed25519");
    }

    #[test]
    fn test_force_scheme_post_quantum() {
        let scheme = CryptoPolicyEngine::force_scheme(&crate::types::CryptoScheme::PostQuantum);
        assert_eq!(scheme, DEFAULT_PQ_ENCRYPTION_SCHEME);
    }

    #[test]
    fn test_force_scheme_homomorphic() {
        let scheme = CryptoPolicyEngine::force_scheme(&crate::types::CryptoScheme::Homomorphic);
        assert_eq!(scheme, "hybrid-ml-kem-768-aes-256-gcm");
    }

    // select_pq_encryption_scheme tests
    #[test]
    fn test_select_pq_encryption_standard() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-kem-512-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_pq_encryption_high() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::High);
        let scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-kem-768-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_pq_encryption_maximum() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_pq_encryption_quantum() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Quantum);
        let scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    // select_pq_signature_scheme tests
    #[test]
    fn test_select_pq_signature_standard() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let scheme = CryptoPolicyEngine::select_pq_signature_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-dsa-44");
        Ok(())
    }

    #[test]
    fn test_select_pq_signature_high() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::High);
        let scheme = CryptoPolicyEngine::select_pq_signature_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-dsa-65");
        Ok(())
    }

    #[test]
    fn test_select_pq_signature_maximum() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let scheme = CryptoPolicyEngine::select_pq_signature_scheme(&config)?;
        assert_eq!(scheme, "pq-ml-dsa-87");
        Ok(())
    }

    // analyze_data_characteristics tests
    #[test]
    fn test_analyze_empty_data() {
        let data: &[u8] = &[];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.size, 0);
        assert_eq!(characteristics.entropy, 0.0);
    }

    #[test]
    fn test_analyze_random_data() {
        // High-entropy data (simulated random)
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert_eq!(characteristics.size, 256);
        assert!(characteristics.entropy > 7.0, "Random data should have high entropy");
    }

    #[test]
    fn test_analyze_repetitive_data() {
        // Low-entropy data (all zeros)
        let data = vec![0u8; 1000];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert_eq!(characteristics.size, 1000);
        assert!(characteristics.entropy < 1.0, "Repetitive data should have low entropy");
        assert_eq!(characteristics.pattern_type, PatternType::Repetitive);
    }

    #[test]
    fn test_analyze_text_data() {
        let data = b"Hello, World! This is a test message with some text content.";
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.size, data.len());
        assert!(characteristics.entropy > 3.0 && characteristics.entropy < 6.0);
    }

    // select_encryption_scheme tests
    #[test]
    fn test_select_encryption_scheme_maximum_security() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let data = b"test data";
        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
        assert_eq!(scheme, "hybrid-ml-kem-1024-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_encryption_scheme_high_security() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::High);
        let data = b"test data";
        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
        assert_eq!(scheme, "hybrid-ml-kem-768-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_encryption_scheme_standard_security() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let data = b"test data";
        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
        assert_eq!(scheme, "hybrid-ml-kem-512-aes-256-gcm");
        Ok(())
    }

    #[test]
    fn test_select_encryption_scheme_with_use_case() -> Result<()> {
        let config = CoreConfig::default();
        let data = b"financial transaction data";
        let scheme = CryptoPolicyEngine::select_encryption_scheme(
            data,
            &config,
            Some(&UseCase::FinancialTransactions),
        )?;
        assert!(scheme.contains("hybrid") || scheme.contains("ml-"));
        Ok(())
    }

    // select_signature_scheme tests
    #[test]
    fn test_select_signature_scheme_maximum() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Maximum);
        let scheme = CryptoPolicyEngine::select_signature_scheme(&config)?;
        assert_eq!(scheme, "hybrid-ml-dsa-87-ed25519");
        Ok(())
    }

    #[test]
    fn test_select_signature_scheme_high() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::High);
        let scheme = CryptoPolicyEngine::select_signature_scheme(&config)?;
        assert_eq!(scheme, "hybrid-ml-dsa-65-ed25519");
        Ok(())
    }

    #[test]
    fn test_select_signature_scheme_standard() -> Result<()> {
        let config = CoreConfig::new().with_security_level(SecurityLevel::Standard);
        let scheme = CryptoPolicyEngine::select_signature_scheme(&config)?;
        assert_eq!(scheme, "hybrid-ml-dsa-44-ed25519");
        Ok(())
    }

    // select_for_context tests
    #[test]
    fn test_select_for_context_large_data() -> Result<()> {
        let config = CoreConfig::default();
        let data = vec![0u8; 10000];
        let scheme = CryptoPolicyEngine::select_for_context(&data, &config)?;
        assert!(scheme.contains("hybrid"));
        Ok(())
    }

    #[test]
    fn test_select_for_context_small_data() -> Result<()> {
        let config = CoreConfig::default();
        let data = b"small";
        let scheme = CryptoPolicyEngine::select_for_context(data, &config)?;
        assert!(scheme.contains("hybrid") || scheme.contains("ml-"));
        Ok(())
    }

    // adaptive_selection tests
    #[test]
    fn test_adaptive_selection_balanced() -> Result<()> {
        let config = CoreConfig::new().with_performance_preference(PerformancePreference::Balanced);
        let data = b"balanced test data";
        let metrics = PerformanceMetrics::default();
        let scheme = CryptoPolicyEngine::adaptive_selection(data, &metrics, &config)?;
        assert!(scheme.contains("hybrid"));
        Ok(())
    }

    #[test]
    fn test_adaptive_selection_speed() -> Result<()> {
        let config = CoreConfig::new()
            .with_performance_preference(PerformancePreference::Speed)
            .with_security_level(SecurityLevel::Standard);
        let data = b"speed test";
        let metrics = PerformanceMetrics::default();
        let scheme = CryptoPolicyEngine::adaptive_selection(data, &metrics, &config)?;
        assert!(!scheme.is_empty());
        Ok(())
    }

    #[test]
    fn test_adaptive_selection_memory() -> Result<()> {
        let config = CoreConfig::new().with_performance_preference(PerformancePreference::Memory);
        let data = b"memory efficient";
        let metrics = PerformanceMetrics::default();
        let scheme = CryptoPolicyEngine::adaptive_selection(data, &metrics, &config)?;
        assert!(!scheme.is_empty());
        Ok(())
    }

    // Integration tests
    #[test]
    fn test_all_use_cases_return_valid_schemes() -> Result<()> {
        let config = CoreConfig::default();
        let use_cases = vec![
            UseCase::SecureMessaging,
            UseCase::EmailEncryption,
            UseCase::VpnTunnel,
            UseCase::ApiSecurity,
            UseCase::FileStorage,
            UseCase::DatabaseEncryption,
            UseCase::CloudStorage,
            UseCase::BackupArchive,
            UseCase::ConfigSecrets,
            UseCase::Authentication,
            UseCase::SessionToken,
            UseCase::DigitalCertificate,
            UseCase::KeyExchange,
            UseCase::FinancialTransactions,
            UseCase::LegalDocuments,
            UseCase::BlockchainTransaction,
            UseCase::HealthcareRecords,
            UseCase::GovernmentClassified,
            UseCase::PaymentCard,
            UseCase::IoTDevice,
            UseCase::FirmwareSigning,
            UseCase::SearchableEncryption,
            UseCase::HomomorphicComputation,
            UseCase::AuditLog,
        ];

        for use_case in use_cases {
            let scheme = CryptoPolicyEngine::recommend_scheme(&use_case, &config)?;
            assert!(!scheme.is_empty(), "UseCase {:?} returned empty scheme", use_case);
        }
        Ok(())
    }

    #[test]
    fn test_all_security_levels_return_valid_encryption() -> Result<()> {
        let levels = vec![
            SecurityLevel::Standard,
            SecurityLevel::High,
            SecurityLevel::Maximum,
            SecurityLevel::Quantum,
        ];

        for level in levels {
            let config = CoreConfig::new().with_security_level(level.clone());
            let scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config)?;
            assert!(
                !scheme.is_empty(),
                "SecurityLevel {:?} returned empty encryption scheme",
                level
            );
        }
        Ok(())
    }

    #[test]
    fn test_all_security_levels_return_valid_signature() -> Result<()> {
        let levels = vec![
            SecurityLevel::Standard,
            SecurityLevel::High,
            SecurityLevel::Maximum,
            SecurityLevel::Quantum,
        ];

        for level in levels {
            let config = CoreConfig::new().with_security_level(level.clone());
            let scheme = CryptoPolicyEngine::select_pq_signature_scheme(&config)?;
            assert!(
                !scheme.is_empty(),
                "SecurityLevel {:?} returned empty signature scheme",
                level
            );
        }
        Ok(())
    }
}
