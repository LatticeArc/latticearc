#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Configuration types for LatticeArc cryptographic operations.
//!
//! This module provides configuration structures for various cryptographic operations
//! including encryption, signatures, key derivation, hardware acceleration, and
//! zero-trust settings.

use std::collections::HashMap;

use crate::unified_api::{
    HardwareType,
    error::CryptoError,
    types::{
        ClassicalScheme, CryptoContext, CryptoScheme, HardwarePreference, PerformancePreference,
        SecurityLevel,
    },
};

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub security_level: SecurityLevel,
    pub performance_preference: PerformancePreference,
    pub hardware_preference: HardwarePreference,
    pub use_hardware_acceleration: bool,
    pub preferred_schemes: Vec<CryptoScheme>,
    pub custom_parameters: HashMap<String, Vec<u8>>,
    pub enable_compression: bool,
    pub enable_serialization: bool,
    pub cache_keys: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Standard,
            performance_preference: PerformancePreference::Balanced,
            hardware_preference: HardwarePreference::Auto,
            use_hardware_acceleration: true,
            preferred_schemes: vec![
                CryptoScheme::HybridPq,
                CryptoScheme::Classical(ClassicalScheme::Aes256Gcm),
            ],
            custom_parameters: HashMap::new(),
            enable_compression: false,
            enable_serialization: true,
            cache_keys: true,
        }
    }
}

impl CryptoConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    pub fn with_performance_preference(mut self, pref: PerformancePreference) -> Self {
        self.performance_preference = pref;
        self
    }

    pub fn with_hardware_preference(mut self, pref: HardwarePreference) -> Self {
        self.hardware_preference = pref;
        self
    }

    pub fn with_hardware_acceleration(mut self, enable: bool) -> Self {
        self.use_hardware_acceleration = enable;
        self
    }

    pub fn with_scheme(mut self, scheme: CryptoScheme) -> Self {
        self.preferred_schemes = vec![scheme];
        self
    }

    pub fn with_schemes(mut self, schemes: Vec<CryptoScheme>) -> Self {
        self.preferred_schemes = schemes;
        self
    }

    pub fn with_custom_parameter(mut self, key: String, value: Vec<u8>) -> Self {
        self.custom_parameters.insert(key, value);
        self
    }

    pub fn with_compression(mut self, enable: bool) -> Self {
        self.enable_compression = enable;
        self
    }

    pub fn with_serialization(mut self, enable: bool) -> Self {
        self.enable_serialization = enable;
        self
    }

    pub fn with_key_caching(mut self, enable: bool) -> Self {
        self.cache_keys = enable;
        self
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        match self.security_level {
            SecurityLevel::Custom { security_bits } if security_bits > 512 => {
                return Err(CryptoError::ConfigurationError(format!(
                    "Security bits {} exceeds maximum 512",
                    security_bits
                )));
            }
            _ => {}
        }

        if self.preferred_schemes.is_empty() {
            return Err(CryptoError::ConfigurationError(
                "At least one preferred scheme must be specified".to_string(),
            ));
        }

        Ok(())
    }

    pub fn to_context(&self) -> CryptoContext {
        CryptoContext {
            security_level: self.security_level,
            performance_preference: self.performance_preference,
            hardware_preference: self.hardware_preference,
            custom_params: if self.custom_parameters.is_empty() {
                None
            } else {
                Some(self.custom_parameters.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub base: CryptoConfig,
    pub use_aead: bool,
    pub nonce_strategy: NonceStrategy,
    pub tag_size: usize,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            base: CryptoConfig::default(),
            use_aead: true,
            nonce_strategy: NonceStrategy::Random,
            tag_size: 16,
        }
    }
}

impl EncryptionConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base(mut self, base: CryptoConfig) -> Self {
        self.base = base;
        self
    }

    pub fn with_aead(mut self, use_aead: bool) -> Self {
        self.use_aead = use_aead;
        self
    }

    pub fn with_nonce_strategy(mut self, strategy: NonceStrategy) -> Self {
        self.nonce_strategy = strategy;
        self
    }

    pub fn with_tag_size(mut self, size: usize) -> Self {
        self.tag_size = size;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceStrategy {
    Random,
    Counter,
    Deterministic,
    Custom(&'static [u8]),
}

#[derive(Debug, Clone)]
pub struct SignatureConfig {
    pub base: CryptoConfig,
    pub deterministic_signatures: bool,
    pub include_timestamp: bool,
    pub include_context: bool,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            base: CryptoConfig::default(),
            deterministic_signatures: false,
            include_timestamp: true,
            include_context: false,
        }
    }
}

impl SignatureConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base(mut self, base: CryptoConfig) -> Self {
        self.base = base;
        self
    }

    pub fn with_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic_signatures = deterministic;
        self
    }

    pub fn with_timestamp(mut self, include: bool) -> Self {
        self.include_timestamp = include;
        self
    }

    pub fn with_context(mut self, include: bool) -> Self {
        self.include_context = include;
        self
    }
}

#[derive(Debug, Clone)]
pub struct KeyDerivationConfig {
    pub base: CryptoConfig,
    pub algorithm: KdfAlgorithm,
    pub iterations: u32,
    pub salt_length: usize,
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            base: CryptoConfig::default(),
            algorithm: KdfAlgorithm::Hkdf,
            iterations: 1,
            salt_length: 32,
        }
    }
}

impl KeyDerivationConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base(mut self, base: CryptoConfig) -> Self {
        self.base = base;
        self
    }

    pub fn with_algorithm(mut self, algorithm: KdfAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    pub fn with_salt_length(mut self, length: usize) -> Self {
        self.salt_length = length;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Hkdf,
    Pbkdf2,
    Argon2,
    Scrypt,
}

#[derive(Debug, Clone)]
pub struct HardwareConfig {
    pub enable_acceleration: bool,
    pub fallback_to_cpu: bool,
    pub acceleration_threshold: usize,
    pub preferred_accelerators: Vec<HardwareType>,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            enable_acceleration: true,
            fallback_to_cpu: true,
            acceleration_threshold: 1024,
            preferred_accelerators: vec![],
        }
    }
}

impl HardwareConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_acceleration(mut self, enable: bool) -> Self {
        self.enable_acceleration = enable;
        self
    }

    pub fn with_fallback(mut self, fallback: bool) -> Self {
        self.fallback_to_cpu = fallback;
        self
    }

    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.acceleration_threshold = threshold;
        self
    }

    pub fn with_preferred_accelerator(mut self, hardware: HardwareType) -> Self {
        self.preferred_accelerators.push(hardware);
        self
    }
}

#[derive(Debug, Clone)]
pub struct ZeroTrustConfig {
    pub enable_zero_knowledge: bool,
    pub enable_continuous_verification: bool,
    pub verification_interval: u64,
    pub proof_complexity: ProofComplexity,
}

impl Default for ZeroTrustConfig {
    fn default() -> Self {
        Self {
            enable_zero_knowledge: true,
            enable_continuous_verification: false,
            verification_interval: 60,
            proof_complexity: ProofComplexity::Standard,
        }
    }
}

impl ZeroTrustConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_zero_knowledge(mut self, enable: bool) -> Self {
        self.enable_zero_knowledge = enable;
        self
    }

    pub fn with_continuous_verification(mut self, enable: bool) -> Self {
        self.enable_continuous_verification = enable;
        self
    }

    pub fn with_interval(mut self, seconds: u64) -> Self {
        self.verification_interval = seconds;
        self
    }

    pub fn with_proof_complexity(mut self, complexity: ProofComplexity) -> Self {
        self.proof_complexity = complexity;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofComplexity {
    Simple,
    Standard,
    High,
    Maximum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerformanceConfig {
    pub enable_parallel: bool,
    pub enable_simd: bool,
    pub enable_caching: bool,
    pub parallel_threads: Option<usize>,
    pub batch_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_parallel: true,
            enable_simd: true,
            enable_caching: true,
            parallel_threads: None,
            batch_size: 4096,
        }
    }
}

impl PerformanceConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_parallel(mut self, enable: bool) -> Self {
        self.enable_parallel = enable;
        self
    }

    pub fn with_simd(mut self, enable: bool) -> Self {
        self.enable_simd = enable;
        self
    }

    pub fn with_caching(mut self, enable: bool) -> Self {
        self.enable_caching = enable;
        self
    }

    pub fn with_parallel_threads(mut self, threads: usize) -> Self {
        self.parallel_threads = Some(threads);
        self
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    pub fn get_parallel_threads(&self) -> usize {
        self.parallel_threads.unwrap_or_else(rayon::current_num_threads)
    }
}
