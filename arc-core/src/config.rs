//! Configuration types for LatticeArc cryptographic operations.
//!
//! Provides hierarchical configuration for encryption, signatures, zero-trust
//! authentication, and hardware acceleration.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::{
    error::{CoreError, Result},
    types::{CryptoScheme, PerformancePreference, SecurityLevel, UseCase},
};

/// Core cryptographic configuration settings.
///
/// This struct provides the foundational configuration that all specialized
/// configurations inherit from. Settings here affect all cryptographic operations.
///
/// # Security Level
/// - `Standard`: 128-bit security, suitable for most applications
/// - `High`: 192-bit security, recommended for sensitive data
/// - `Maximum`: 256-bit security, for high-value assets
///
/// # Examples
/// ```rust
/// use arc_core::config::CoreConfig;
/// use arc_core::types::{SecurityLevel, PerformancePreference};
///
/// // Create a high-security configuration
/// let config = CoreConfig::new()
///     .with_security_level(SecurityLevel::High)
///     .with_performance_preference(PerformancePreference::Balanced)
///     .build()
///     .expect("Failed to build config");
///
/// // Use for development with relaxed settings
/// let dev_config = CoreConfig::for_development();
///
/// // Use for production with maximum security
/// let prod_config = CoreConfig::for_production();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    /// Security level for cryptographic operations.
    ///
    /// Higher security levels provide stronger protection but may impact performance.
    /// Default: `SecurityLevel::High`
    pub security_level: SecurityLevel,

    /// Performance preference for cryptographic operations.
    ///
    /// Affects algorithm selection and optimization strategies.
    /// Default: `PerformancePreference::Balanced`
    pub performance_preference: PerformancePreference,

    /// Whether hardware acceleration is enabled.
    ///
    /// Uses CPU features like AVX2/AVX-512 or GPU acceleration when available.
    /// Default: `true`
    pub hardware_acceleration: bool,

    /// Whether fallback to software implementations is enabled.
    ///
    /// If hardware acceleration fails, fallback to portable software implementations.
    /// Default: `true`
    pub fallback_enabled: bool,

    /// Whether strict validation is enabled.
    ///
    /// Performs additional validation checks that may impact performance.
    /// Default: `true`
    pub strict_validation: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            // Security level is High by default to prioritize security over performance
            // for most applications. Override with .with_performance_preference()
            // for performance-critical workloads.
            security_level: SecurityLevel::High,

            // Balanced performance provides good performance with reasonable security.
            // Use Speed for high-throughput applications, Memory for memory-constrained environments.
            performance_preference: PerformancePreference::Balanced,

            // Hardware acceleration is enabled by default for better performance.
            // Disable only if hardware acceleration causes issues.
            hardware_acceleration: true,

            // Fallback is enabled to ensure compatibility across different hardware.
            // Disable only for performance-critical applications with known hardware.
            fallback_enabled: true,

            // Strict validation is enabled by default for maximum security.
            // Disable for performance-critical applications where you've validated inputs.
            strict_validation: true,
        }
    }
}

impl CoreConfig {
    /// Create a new configuration with sensible defaults.
    ///
    /// This provides a balanced configuration suitable for most applications.
    /// For specific use cases, use the builder methods or environment-specific constructors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration optimized for development.
    ///
    /// Uses relaxed security settings to prioritize development speed over security.
    /// Not suitable for production use.
    #[must_use]
    pub fn for_development() -> Self {
        Self::default().with_security_level(SecurityLevel::Standard).with_strict_validation(false)
    }

    /// Create a configuration optimized for production.
    ///
    /// Uses maximum security settings suitable for production environments.
    #[must_use]
    pub fn for_production() -> Self {
        Self::default().with_security_level(SecurityLevel::Maximum).with_strict_validation(true)
    }

    /// Set the security level and return self for method chaining.
    #[must_use]
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    /// Set the performance preference and return self for method chaining.
    #[must_use]
    pub fn with_performance_preference(mut self, preference: PerformancePreference) -> Self {
        self.performance_preference = preference;
        self
    }

    /// Set hardware acceleration and return self for method chaining.
    #[must_use]
    pub fn with_hardware_acceleration(mut self, enabled: bool) -> Self {
        self.hardware_acceleration = enabled;
        self
    }

    /// Set fallback mode and return self for method chaining.
    #[must_use]
    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    /// Set strict validation and return self for method chaining.
    #[must_use]
    pub fn with_strict_validation(mut self, enabled: bool) -> Self {
        self.strict_validation = enabled;
        self
    }

    /// Build and validate the configuration.
    ///
    /// Performs comprehensive validation of the configuration and returns
    /// a validated configuration ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Maximum security level is configured without hardware acceleration enabled
    /// - Speed performance preference is configured without fallback enabled
    pub fn build(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }

    /// Validates the configuration settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Maximum security level is configured without hardware acceleration enabled
    /// - Speed performance preference is configured without fallback enabled
    pub fn validate(&self) -> Result<()> {
        if matches!(self.security_level, SecurityLevel::Maximum) && !self.hardware_acceleration {
            return Err(CoreError::ConfigurationError(
                "Maximum security level requires hardware acceleration".to_string(),
            ));
        }

        if matches!(self.performance_preference, PerformancePreference::Speed)
            && !self.fallback_enabled
        {
            return Err(CoreError::ConfigurationError(
                "Speed preference should have fallback enabled for reliability".to_string(),
            ));
        }

        Ok(())
    }
}

/// Configuration for encryption operations.
///
/// Extends [`CoreConfig`] with encryption-specific settings like preferred
/// cryptographic scheme, compression, and integrity checking.
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Base configuration inherited from [`CoreConfig`].
    pub base: CoreConfig,
    /// Preferred encryption scheme, or `None` for automatic selection.
    pub preferred_scheme: Option<CryptoScheme>,
    /// Whether to compress data before encryption.
    pub compression_enabled: bool,
    /// Whether to include integrity verification tags.
    pub integrity_check: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            base: CoreConfig::default(),
            preferred_scheme: None,
            compression_enabled: true,
            integrity_check: true,
        }
    }
}

impl EncryptionConfig {
    /// Creates a new encryption configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the preferred encryption scheme.
    #[must_use]
    pub fn with_scheme(mut self, scheme: CryptoScheme) -> Self {
        self.preferred_scheme = Some(scheme);
        self
    }

    /// Enables or disables compression before encryption.
    #[must_use]
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }

    /// Enables or disables integrity checking.
    #[must_use]
    pub fn with_integrity_check(mut self, enabled: bool) -> Self {
        self.integrity_check = enabled;
        self
    }

    /// Validates the encryption configuration settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base configuration validation fails
    /// - Compression is enabled without integrity check enabled
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;

        if self.compression_enabled && !self.integrity_check {
            return Err(CoreError::ConfigurationError(
                "Compression requires integrity check".to_string(),
            ));
        }

        Ok(())
    }
}

/// Configuration for digital signature operations.
///
/// Extends [`CoreConfig`] with signature-specific settings like preferred
/// scheme, timestamping, and certificate chain support.
#[derive(Debug, Clone)]
pub struct SignatureConfig {
    /// Base configuration inherited from [`CoreConfig`].
    pub base: CoreConfig,
    /// Preferred signature scheme, or `None` for automatic selection.
    pub preferred_scheme: Option<CryptoScheme>,
    /// Whether to include timestamps in signatures.
    pub timestamp_enabled: bool,
    /// Whether to include the full certificate chain.
    pub certificate_chain: bool,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            base: CoreConfig::default(),
            preferred_scheme: None,
            timestamp_enabled: true,
            certificate_chain: false,
        }
    }
}

impl SignatureConfig {
    /// Creates a new signature configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the preferred signature scheme.
    #[must_use]
    pub fn with_scheme(mut self, scheme: CryptoScheme) -> Self {
        self.preferred_scheme = Some(scheme);
        self
    }

    /// Enables or disables timestamp inclusion in signatures.
    #[must_use]
    pub fn with_timestamp(mut self, enabled: bool) -> Self {
        self.timestamp_enabled = enabled;
        self
    }

    /// Enables or disables certificate chain inclusion.
    #[must_use]
    pub fn with_certificate_chain(mut self, enabled: bool) -> Self {
        self.certificate_chain = enabled;
        self
    }

    /// Validates the signature configuration settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base configuration validation fails
    /// - Certificate chain is enabled without timestamp enabled
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;

        if self.certificate_chain && !self.timestamp_enabled {
            return Err(CoreError::ConfigurationError(
                "Certificate chain requires timestamp".to_string(),
            ));
        }

        Ok(())
    }
}

/// Configuration for zero-trust authentication operations.
///
/// Extends [`CoreConfig`] with settings for challenge-response authentication,
/// proof complexity, and continuous verification intervals.
#[derive(Debug, Clone)]
pub struct ZeroTrustConfig {
    /// Base configuration inherited from [`CoreConfig`].
    pub base: CoreConfig,
    /// Timeout in milliseconds for challenge responses.
    pub challenge_timeout_ms: u64,
    /// Complexity level for zero-knowledge proofs.
    pub proof_complexity: ProofComplexity,
    /// Whether continuous session verification is enabled.
    pub continuous_verification: bool,
    /// Interval in milliseconds between verification checks.
    pub verification_interval_ms: u64,
}

impl Default for ZeroTrustConfig {
    fn default() -> Self {
        Self {
            base: CoreConfig::default(),
            challenge_timeout_ms: 5000,
            proof_complexity: ProofComplexity::Medium,
            continuous_verification: true,
            verification_interval_ms: 30000,
        }
    }
}

impl ZeroTrustConfig {
    /// Creates a new zero-trust configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the challenge timeout in milliseconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.challenge_timeout_ms = timeout_ms;
        self
    }

    /// Sets the proof complexity level.
    #[must_use]
    pub fn with_complexity(mut self, complexity: ProofComplexity) -> Self {
        self.proof_complexity = complexity;
        self
    }

    /// Enables or disables continuous session verification.
    #[must_use]
    pub fn with_continuous_verification(mut self, enabled: bool) -> Self {
        self.continuous_verification = enabled;
        self
    }

    /// Sets the verification interval in milliseconds.
    #[must_use]
    pub fn with_verification_interval(mut self, interval_ms: u64) -> Self {
        self.verification_interval_ms = interval_ms;
        self
    }

    /// Validates the zero-trust configuration settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base configuration validation fails
    /// - Challenge timeout is set to zero
    /// - Continuous verification is enabled with a zero verification interval
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;

        if self.challenge_timeout_ms == 0 {
            return Err(CoreError::ConfigurationError(
                "Challenge timeout cannot be zero".to_string(),
            ));
        }

        if self.continuous_verification && self.verification_interval_ms == 0 {
            return Err(CoreError::ConfigurationError(
                "Continuous verification requires non-zero interval".to_string(),
            ));
        }

        Ok(())
    }
}

/// Complexity level for zero-knowledge proofs.
///
/// Higher complexity provides stronger security guarantees but requires
/// more computation and bandwidth.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofComplexity {
    /// Low complexity: 32-byte challenges, basic verification.
    Low,
    /// Medium complexity: 64-byte challenges with timestamp binding.
    Medium,
    /// High complexity: 128-byte challenges with timestamp and public key binding.
    High,
}

/// Configuration for hardware acceleration.
///
/// Controls which hardware accelerators are used and under what conditions
/// software fallback is permitted.
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    /// Whether hardware acceleration is enabled.
    pub acceleration_enabled: bool,
    /// Whether software fallback is permitted when hardware is unavailable.
    pub fallback_enabled: bool,
    /// Minimum data size in bytes to trigger hardware acceleration.
    pub threshold_bytes: usize,
    /// List of preferred hardware accelerators in priority order.
    pub preferred_accelerators: Vec<crate::traits::HardwareType>,
    /// Force CPU-only mode, bypassing all other accelerators.
    pub force_cpu: bool,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            acceleration_enabled: true,
            fallback_enabled: true,
            threshold_bytes: 4096,
            preferred_accelerators: Vec::new(),
            force_cpu: false,
        }
    }
}

impl HardwareConfig {
    /// Creates a new hardware configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables or disables hardware acceleration.
    #[must_use]
    pub fn with_acceleration(mut self, enabled: bool) -> Self {
        self.acceleration_enabled = enabled;
        self
    }

    /// Enables or disables software fallback.
    #[must_use]
    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    /// Sets the minimum data size threshold for hardware acceleration.
    #[must_use]
    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold_bytes = threshold;
        self
    }

    /// Adds a preferred accelerator to the priority list.
    #[must_use]
    pub fn with_preferred_accelerator(mut self, accelerator: crate::traits::HardwareType) -> Self {
        self.preferred_accelerators.push(accelerator);
        self
    }

    /// Forces CPU-only mode, bypassing all accelerators.
    #[must_use]
    pub fn with_force_cpu(mut self, force: bool) -> Self {
        self.force_cpu = force;
        self
    }

    /// Validates the hardware configuration settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hardware threshold bytes is set to zero
    /// - Force CPU mode is enabled while acceleration is also enabled
    pub fn validate(&self) -> Result<()> {
        if self.threshold_bytes == 0 {
            return Err(CoreError::ConfigurationError(
                "Hardware threshold cannot be zero".to_string(),
            ));
        }

        if self.force_cpu && self.acceleration_enabled {
            return Err(CoreError::ConfigurationError(
                "Force CPU conflicts with acceleration enabled".to_string(),
            ));
        }

        Ok(())
    }
}

/// Configuration tailored for a specific use case.
///
/// Combines encryption, signature, zero-trust, and hardware configurations
/// with settings optimized for the given use case.
#[derive(Debug, Clone)]
pub struct UseCaseConfig {
    /// The use case this configuration is optimized for.
    pub use_case: UseCase,
    /// Encryption configuration for this use case.
    pub encryption: EncryptionConfig,
    /// Signature configuration for this use case.
    pub signature: SignatureConfig,
    /// Zero-trust configuration for this use case.
    pub zero_trust: ZeroTrustConfig,
    /// Hardware configuration for this use case.
    pub hardware: HardwareConfig,
}

impl UseCaseConfig {
    /// Creates a new configuration optimized for the specified use case.
    #[must_use]
    pub fn new(use_case: UseCase) -> Self {
        let base_config = match use_case {
            // Communication: Low latency requirements
            UseCase::SecureMessaging | UseCase::ApiSecurity => {
                CoreConfig::new().with_performance_preference(PerformancePreference::Speed)
            }
            UseCase::EmailEncryption => CoreConfig::new().with_security_level(SecurityLevel::High),
            UseCase::VpnTunnel => CoreConfig::new()
                .with_performance_preference(PerformancePreference::Speed)
                .with_hardware_acceleration(true),

            // Storage: Long-term security
            UseCase::FileStorage | UseCase::CloudStorage | UseCase::BackupArchive => {
                CoreConfig::new().with_security_level(SecurityLevel::Maximum)
            }
            UseCase::DatabaseEncryption | UseCase::ConfigSecrets => {
                CoreConfig::new().with_performance_preference(PerformancePreference::Memory)
            }

            // Authentication & Identity
            UseCase::Authentication | UseCase::DigitalCertificate => {
                CoreConfig::new().with_security_level(SecurityLevel::Maximum)
            }
            UseCase::SessionToken => {
                CoreConfig::new().with_performance_preference(PerformancePreference::Speed)
            }
            UseCase::KeyExchange => CoreConfig::new().with_security_level(SecurityLevel::Maximum),

            // Financial & Legal: Highest security
            UseCase::FinancialTransactions | UseCase::LegalDocuments => {
                CoreConfig::new().with_security_level(SecurityLevel::Maximum)
            }
            UseCase::BlockchainTransaction => {
                CoreConfig::new().with_performance_preference(PerformancePreference::Balanced)
            }

            // Regulated Industries: Maximum security + compliance
            UseCase::HealthcareRecords | UseCase::GovernmentClassified | UseCase::PaymentCard => {
                CoreConfig::new().with_security_level(SecurityLevel::Maximum)
            }

            // IoT & Embedded: Resource-constrained
            UseCase::IoTDevice => CoreConfig::new()
                .with_security_level(SecurityLevel::Standard)
                .with_performance_preference(PerformancePreference::Memory),
            UseCase::FirmwareSigning => CoreConfig::new().with_security_level(SecurityLevel::High),

            // Advanced: Specialized requirements
            UseCase::SearchableEncryption => CoreConfig::default(),
            UseCase::HomomorphicComputation => CoreConfig::new()
                .with_security_level(SecurityLevel::Maximum)
                .with_hardware_acceleration(true),
            UseCase::AuditLog => CoreConfig::new().with_security_level(SecurityLevel::High),
        };

        Self {
            use_case,
            encryption: EncryptionConfig { base: base_config.clone(), ..Default::default() },
            signature: SignatureConfig { base: base_config.clone(), ..Default::default() },
            zero_trust: ZeroTrustConfig { base: base_config, ..Default::default() },
            hardware: HardwareConfig::default(),
        }
    }

    /// Validates all nested configuration settings for the use case.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the nested configurations fail validation:
    /// - Encryption configuration validation fails
    /// - Signature configuration validation fails
    /// - Zero-trust configuration validation fails
    /// - Hardware configuration validation fails
    pub fn validate(&self) -> Result<()> {
        self.encryption.validate()?;
        self.signature.validate()?;
        self.zero_trust.validate()?;
        self.hardware.validate()?;
        Ok(())
    }
}
