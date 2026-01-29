#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Cryptographic policy engine for automatic algorithm selection.
//!
//! This module provides intelligent cryptographic scheme selection based on
//! data characteristics, security requirements, and performance preferences.
//! It analyzes data entropy, structure, and size to recommend optimal encryption schemes.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::unified_api::{
    DataCharacteristics, DataStructure,
    config::{CryptoConfig, EncryptionConfig},
    error::CryptoError,
    types::{
        ClassicalScheme, CryptoContext, CryptoScheme, HomomorphicScheme, MpcScheme, OreScheme,
        PerformancePreference, SecurityLevel, SseScheme,
    },
};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    size: usize,
    data_hash: u64,
}

impl CacheKey {
    fn new(data: &[u8]) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write_usize(data.len());

        if !data.is_empty() {
            let sample_size = data.len().min(256);
            hasher.write(&data[..sample_size]);
        }

        Self { size: data.len(), data_hash: hasher.finish() }
    }
}

pub struct CryptoPolicyEngine;

lazy_static::lazy_static! {
    static ref CHARACTERISTICS_CACHE: Arc<Mutex<HashMap<CacheKey, DataCharacteristics>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

impl CryptoPolicyEngine {
    pub fn select_encryption_scheme(
        data: &[u8],
        config: &EncryptionConfig,
        use_case: Option<UseCase>,
    ) -> Result<CryptoScheme, CryptoError> {
        let characteristics = Self::analyze_data_characteristics_cached(data);
        let ctx = &config.base.to_context();

        if let Some(uc) = use_case {
            return Ok(Self::recommend_scheme(
                uc,
                config.base.security_level,
                config.base.performance_preference,
            ));
        }

        if !config.base.preferred_schemes.is_empty() {
            return Ok(config.base.preferred_schemes[0]);
        }

        Self::select_optimal_encryption_scheme(&characteristics, ctx)
    }

    pub fn select_signature_scheme(config: &CryptoConfig) -> Result<CryptoScheme, CryptoError> {
        let ctx = &config.to_context();

        if !config.preferred_schemes.is_empty() {
            for scheme in &config.preferred_schemes {
                if Self::is_signature_scheme(scheme) {
                    return Ok(*scheme);
                }
            }
        }

        Self::select_optimal_signature_scheme(ctx)
    }

    pub fn select_hash_scheme(_config: &CryptoConfig) -> Result<CryptoScheme, CryptoError> {
        Ok(CryptoScheme::Classical(ClassicalScheme::Aes256Gcm))
    }

    pub fn select_with_override(
        data: &[u8],
        config: &EncryptionConfig,
        preferred_scheme: Option<CryptoScheme>,
    ) -> Result<CryptoScheme, CryptoError> {
        if let Some(scheme) = preferred_scheme {
            return Ok(scheme);
        }

        Self::select_encryption_scheme(data, config, None)
    }

    pub fn select_optimal_encryption_scheme(
        characteristics: &DataCharacteristics,
        ctx: &CryptoContext,
    ) -> Result<CryptoScheme, CryptoError> {
        match ctx.security_level {
            SecurityLevel::Standard | SecurityLevel::High => match characteristics.structure {
                DataStructure::Numeric => Ok(CryptoScheme::OrderRevealing(OreScheme::Basic)),
                DataStructure::Text => Ok(CryptoScheme::Searchable(SseScheme::Deterministic)),
                DataStructure::Structured => {
                    if ctx.performance_preference == PerformancePreference::Speed {
                        Ok(CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305))
                    } else {
                        Ok(CryptoScheme::HybridPq)
                    }
                }
                DataStructure::Binary => {
                    if characteristics.entropy > 7.5 {
                        Ok(CryptoScheme::HybridPq)
                    } else {
                        Self::select_by_performance(ctx.performance_preference)
                    }
                }
                DataStructure::Unstructured => {
                    Self::select_by_performance(ctx.performance_preference)
                }
            },
            SecurityLevel::Maximum => Ok(CryptoScheme::HybridPq),
            SecurityLevel::Custom { security_bits } if security_bits >= 256 => {
                Ok(CryptoScheme::HybridPq)
            }
            _ => Self::select_by_performance(ctx.performance_preference),
        }
    }

    pub fn select_optimal_signature_scheme(
        ctx: &CryptoContext,
    ) -> Result<CryptoScheme, CryptoError> {
        match ctx.security_level {
            SecurityLevel::Maximum => Ok(CryptoScheme::Classical(ClassicalScheme::Ed25519)),
            _ => Ok(CryptoScheme::Classical(ClassicalScheme::Ed25519)),
        }
    }

    fn select_by_performance(pref: PerformancePreference) -> Result<CryptoScheme, CryptoError> {
        match pref {
            PerformancePreference::Speed | PerformancePreference::Latency => {
                Ok(CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305))
            }
            PerformancePreference::Throughput => {
                Ok(CryptoScheme::Classical(ClassicalScheme::Aes256Gcm))
            }
            PerformancePreference::Memory => {
                Ok(CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305))
            }
            PerformancePreference::Balanced => Ok(CryptoScheme::HybridPq),
        }
    }

    fn analyze_data_characteristics_cached(data: &[u8]) -> DataCharacteristics {
        let cache_key = CacheKey::new(data);

        {
            let cache = CHARACTERISTICS_CACHE.lock();
            if let Some(cached) = cache.get(&cache_key) {
                return *cached;
            }
        }

        let characteristics = Self::analyze_data_characteristics_uncached(data);

        {
            let mut cache = CHARACTERISTICS_CACHE.lock();
            if cache.len() < 1000 {
                cache.insert(cache_key, characteristics);
            }
        }

        characteristics
    }

    pub fn analyze_data_characteristics(data: &[u8]) -> DataCharacteristics {
        Self::analyze_data_characteristics_cached(data)
    }

    fn analyze_data_characteristics_uncached(data: &[u8]) -> DataCharacteristics {
        let size = data.len();
        let entropy = Self::calculate_entropy(data);
        let compressibility = Self::estimate_compressibility(data, entropy);
        let structure = Self::detect_structure(data);

        DataCharacteristics { size, entropy, compressibility, structure }
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq: HashMap<u8, usize> = HashMap::new();
        for &byte in data {
            *freq.entry(byte).or_insert(0) += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for count in freq.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    fn estimate_compressibility(data: &[u8], entropy: f64) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let max_entropy = 8.0;
        if entropy >= max_entropy * 0.9 {
            0.0
        } else if entropy >= max_entropy * 0.7 {
            0.3
        } else if entropy >= max_entropy * 0.5 {
            0.6
        } else {
            0.9
        }
    }

    fn detect_structure(data: &[u8]) -> DataStructure {
        if data.is_empty() {
            return DataStructure::Unstructured;
        }

        let printable_ratio = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count()
            as f64
            / data.len() as f64;

        if printable_ratio > 0.8 {
            let data_str = String::from_utf8_lossy(data);
            if data_str.contains('{')
                || data_str.contains('}')
                || data_str.contains('<')
                || data_str.contains('>')
            {
                DataStructure::Structured
            } else if data.iter().all(|&b| {
                b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'+' || b == b'e' || b == b'E'
            }) {
                DataStructure::Numeric
            } else {
                DataStructure::Text
            }
        } else if data.iter().all(|&b| b.is_ascii_digit() || b == b'.' || b == b'-') {
            DataStructure::Numeric
        } else {
            DataStructure::Binary
        }
    }

    pub fn is_signature_scheme(scheme: &CryptoScheme) -> bool {
        matches!(
            scheme,
            CryptoScheme::Classical(ClassicalScheme::Ed25519)
                | CryptoScheme::Classical(ClassicalScheme::P256)
        )
    }

    pub fn force_scheme(scheme: CryptoScheme) -> CryptoConfig {
        CryptoConfig { preferred_schemes: vec![scheme], ..Default::default() }
    }

    pub fn recommend_scheme(
        use_case: UseCase,
        security_level: SecurityLevel,
        performance: PerformancePreference,
    ) -> CryptoScheme {
        match (use_case, security_level, performance) {
            (UseCase::Messaging, SecurityLevel::Maximum, _) | (UseCase::Messaging, _, _) => {
                CryptoScheme::HybridPq
            }

            (UseCase::Database, SecurityLevel::Maximum, _) => CryptoScheme::HybridPq,
            (UseCase::Database, _, PerformancePreference::Speed) => {
                CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
            }
            (UseCase::Database, _, PerformancePreference::Throughput) => {
                CryptoScheme::Classical(ClassicalScheme::Aes256Gcm)
            }
            (UseCase::Database, _, _) => CryptoScheme::Classical(ClassicalScheme::Aes256Gcm),

            (UseCase::Searchable, _, _) => CryptoScheme::Searchable(SseScheme::Deterministic),

            (UseCase::MachineLearning, SecurityLevel::Maximum, _) => {
                CryptoScheme::Homomorphic(HomomorphicScheme::CKKS)
            }
            (UseCase::MachineLearning, _, _) => {
                CryptoScheme::Homomorphic(HomomorphicScheme::Paillier)
            }

            (UseCase::MultiPartyComputation, _, _) => CryptoScheme::MultiParty(MpcScheme::FROST),

            (UseCase::SecureAnalytics, SecurityLevel::Maximum, _) => {
                CryptoScheme::Homomorphic(HomomorphicScheme::CKKS)
            }
            (UseCase::SecureAnalytics, _, _) => {
                CryptoScheme::Homomorphic(HomomorphicScheme::Paillier)
            }

            (UseCase::HighSecurity, SecurityLevel::Maximum, _) => CryptoScheme::HybridPq,
            (UseCase::HighSecurity, _, _) => CryptoScheme::HybridPq,

            (UseCase::PerformanceCritical, _, PerformancePreference::Speed) => {
                CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
            }
            (UseCase::PerformanceCritical, _, _) => CryptoScheme::HybridPq,

            (UseCase::EncryptedMessagingE2E, _, _) => CryptoScheme::HybridPq,
            (UseCase::FileStorage, _, _) => CryptoScheme::HybridPq,
            (UseCase::RealTimeStream, _, _) => {
                CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
            }
            (UseCase::IoTEdge, _, _) => CryptoScheme::HybridPq,
            (UseCase::BlockchainWeb3, _, _) => CryptoScheme::HybridPq,
            (UseCase::HighThroughputBatch, _, _) => {
                CryptoScheme::Classical(ClassicalScheme::Aes256Gcm)
            }
            (UseCase::SmallPayload, _, _) => CryptoScheme::HybridPq,
        }
    }

    pub fn select_for_data_size(
        size: usize,
        security_level: SecurityLevel,
        performance: PerformancePreference,
    ) -> CryptoScheme {
        match (size, security_level, performance) {
            (0..=1024, SecurityLevel::Maximum, _) => CryptoScheme::HybridPq,
            (0..=1024, _, PerformancePreference::Speed) => {
                CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
            }
            (0..=1024, _, _) => CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305),

            (1025..=1048576, SecurityLevel::Maximum, _) => CryptoScheme::HybridPq,
            (1025..=1048576, _, PerformancePreference::Speed) => {
                CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
            }
            (1025..=1048576, _, PerformancePreference::Throughput) => {
                CryptoScheme::Classical(ClassicalScheme::Aes256Gcm)
            }
            (1025..=1048576, _, _) => CryptoScheme::HybridPq,

            (_, SecurityLevel::Maximum, _) => CryptoScheme::HybridPq,
            (_, _, PerformancePreference::Throughput) => {
                CryptoScheme::Classical(ClassicalScheme::Aes256Gcm)
            }
            (_, _, PerformancePreference::Speed) => {
                CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
            }
            (_, _, _) => CryptoScheme::HybridPq,
        }
    }

    pub fn estimate_performance_overhead(scheme: &CryptoScheme, data_size: usize) -> f64 {
        let base_overhead = match scheme {
            CryptoScheme::HybridPq => 1.5,
            CryptoScheme::Homomorphic(_) => 10.0,
            CryptoScheme::MultiParty(_) => 5.0,
            CryptoScheme::OrderRevealing(_) => 2.0,
            CryptoScheme::Searchable(_) => 1.8,
            CryptoScheme::Classical(_) => 1.0,
        };

        let size_factor = if data_size < 1024 {
            1.2
        } else if data_size < 1048576 {
            1.0
        } else {
            0.8
        };

        base_overhead * size_factor
    }

    pub fn is_deterministic_selection(
        data: &[u8],
        config: &EncryptionConfig,
        use_case: Option<UseCase>,
    ) -> bool {
        let scheme1 = Self::select_encryption_scheme(data, config, use_case).ok();
        let scheme2 = Self::select_encryption_scheme(data, config, use_case).ok();
        scheme1 == scheme2
    }

    pub fn clear_cache() {
        let mut cache = CHARACTERISTICS_CACHE.lock();
        cache.clear();
    }

    pub fn cache_size() -> usize {
        let cache = CHARACTERISTICS_CACHE.lock();
        cache.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UseCase {
    Messaging,
    Database,
    Searchable,
    MachineLearning,
    MultiPartyComputation,
    SecureAnalytics,
    HighSecurity,
    PerformanceCritical,
    EncryptedMessagingE2E,
    FileStorage,
    RealTimeStream,
    IoTEdge,
    BlockchainWeb3,
    HighThroughputBatch,
    SmallPayload,
}

impl UseCase {
    pub fn all() -> Vec<UseCase> {
        vec![
            UseCase::Messaging,
            UseCase::Database,
            UseCase::Searchable,
            UseCase::MachineLearning,
            UseCase::MultiPartyComputation,
            UseCase::SecureAnalytics,
            UseCase::HighSecurity,
            UseCase::PerformanceCritical,
            UseCase::EncryptedMessagingE2E,
            UseCase::FileStorage,
            UseCase::RealTimeStream,
            UseCase::IoTEdge,
            UseCase::BlockchainWeb3,
            UseCase::HighThroughputBatch,
            UseCase::SmallPayload,
        ]
    }

    pub fn description(&self) -> &'static str {
        match self {
            UseCase::Messaging => "End-to-end encrypted messaging and communication",
            UseCase::Database => "At-rest database encryption and storage",
            UseCase::Searchable => "Searchable encrypted data and queries",
            UseCase::MachineLearning => "Homomorphic computation for ML and data science",
            UseCase::MultiPartyComputation => "Secure multi-party computation protocols",
            UseCase::SecureAnalytics => "Analytics on encrypted data",
            UseCase::HighSecurity => "High-security applications requiring PQ protection",
            UseCase::PerformanceCritical => "Performance-critical applications",
            UseCase::EncryptedMessagingE2E => "End-to-end encrypted messaging with forward secrecy",
            UseCase::FileStorage => "Cloud object storage with compression optimization",
            UseCase::RealTimeStream => "Real-time data stream processing with low latency",
            UseCase::IoTEdge => "Resource-constrained IoT and edge devices",
            UseCase::BlockchainWeb3 => "Blockchain and Web3 smart contracts",
            UseCase::HighThroughputBatch => "High-throughput batch processing with SIMD",
            UseCase::SmallPayload => "Small message and API request optimization",
        }
    }

    pub fn recommended_scheme(
        &self,
        security_level: SecurityLevel,
        performance: PerformancePreference,
    ) -> CryptoScheme {
        CryptoPolicyEngine::recommend_scheme(*self, security_level, performance)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::unified_api::config::EncryptionConfig;

    #[test]
    fn test_analyze_empty_data() {
        let data = [];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert_eq!(characteristics.size, 0);
        assert_eq!(characteristics.entropy, 0.0);
    }

    #[test]
    fn test_analyze_uniform_data() {
        let data = [0u8; 100];
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert_eq!(characteristics.size, 100);
        assert_eq!(characteristics.entropy, 0.0);
        assert_eq!(characteristics.compressibility, 0.9);
    }

    #[test]
    fn test_analyze_random_data() {
        let data: Vec<u8> = (0..256).map(|x| x as u8).collect();
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(&data);
        assert_eq!(characteristics.size, 256);
        assert!(characteristics.entropy > 7.5);
    }

    #[test]
    fn test_detect_text_structure() {
        let data = b"Hello, world! This is a test.";
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.structure, DataStructure::Text);
    }

    #[test]
    fn test_detect_json_structure() {
        let data = br#"{"name": "test", "value": 123}"#;
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.structure, DataStructure::Structured);
    }

    #[test]
    fn test_detect_numeric_structure() {
        let data = b"123.456-789";
        let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert_eq!(characteristics.structure, DataStructure::Numeric);
    }

    #[test]
    fn test_recommend_scheme_messaging() {
        let scheme = CryptoPolicyEngine::recommend_scheme(
            UseCase::Messaging,
            SecurityLevel::Standard,
            PerformancePreference::Balanced,
        );
        assert_eq!(scheme, CryptoScheme::HybridPq);
    }

    #[test]
    fn test_recommend_scheme_database() {
        let scheme = CryptoPolicyEngine::recommend_scheme(
            UseCase::Database,
            SecurityLevel::Standard,
            PerformancePreference::Speed,
        );
        assert_eq!(scheme, CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305));
    }

    #[test]
    fn test_recommend_scheme_ml() {
        let scheme = CryptoPolicyEngine::recommend_scheme(
            UseCase::MachineLearning,
            SecurityLevel::Standard,
            PerformancePreference::Balanced,
        );
        assert_eq!(scheme, CryptoScheme::Homomorphic(HomomorphicScheme::Paillier));
    }

    #[test]
    fn test_recommend_scheme_searchable() {
        let scheme = CryptoPolicyEngine::recommend_scheme(
            UseCase::Searchable,
            SecurityLevel::Standard,
            PerformancePreference::Balanced,
        );
        assert_eq!(scheme, CryptoScheme::Searchable(SseScheme::Deterministic));
    }

    #[test]
    fn test_select_with_use_case() {
        let config = EncryptionConfig::default();
        let data = b"test data";
        let scheme =
            CryptoPolicyEngine::select_encryption_scheme(data, &config, Some(UseCase::Messaging));
        assert!(scheme.is_ok());
        assert_eq!(scheme.unwrap(), CryptoScheme::HybridPq);
    }

    #[test]
    fn test_select_with_override() {
        let config = EncryptionConfig::default();
        let data = b"test data";
        let preferred = CryptoScheme::Classical(ClassicalScheme::Aes256Gcm);
        let scheme = CryptoPolicyEngine::select_with_override(data, &config, Some(preferred));
        assert!(scheme.is_ok());
        assert_eq!(scheme.unwrap(), CryptoScheme::Classical(ClassicalScheme::Aes256Gcm));
    }

    #[test]
    fn test_deterministic_selection() {
        let config = EncryptionConfig::default();
        let data = b"test data for deterministic selection";
        let result = CryptoPolicyEngine::is_deterministic_selection(data, &config, None);
        assert!(result);
    }

    #[test]
    fn test_estimate_performance_overhead() {
        let scheme = CryptoScheme::HybridPq;
        let overhead = CryptoPolicyEngine::estimate_performance_overhead(&scheme, 1024);
        assert!(overhead > 1.0);
    }

    #[test]
    fn test_select_for_data_size() {
        let scheme = CryptoPolicyEngine::select_for_data_size(
            512,
            SecurityLevel::Standard,
            PerformancePreference::Speed,
        );
        assert_eq!(scheme, CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305));
    }

    #[test]
    fn test_force_scheme() {
        let scheme = CryptoScheme::HybridPq;
        let config = CryptoPolicyEngine::force_scheme(scheme);
        assert_eq!(config.preferred_schemes.len(), 1);
        assert_eq!(config.preferred_schemes[0], scheme);
    }

    #[test]
    fn test_use_case_descriptions() {
        assert!(!UseCase::Messaging.description().is_empty());
        assert!(!UseCase::Database.description().is_empty());
    }

    #[test]
    fn test_use_case_recommended_scheme() {
        let scheme = UseCase::Messaging
            .recommended_scheme(SecurityLevel::Maximum, PerformancePreference::Balanced);
        assert_eq!(scheme, CryptoScheme::HybridPq);
    }

    #[test]
    fn test_cache_operations() {
        CryptoPolicyEngine::clear_cache();
        assert_eq!(CryptoPolicyEngine::cache_size(), 0);

        let data = b"test data for caching";
        let _ = CryptoPolicyEngine::analyze_data_characteristics(data);
        assert!(CryptoPolicyEngine::cache_size() > 0);

        CryptoPolicyEngine::clear_cache();
        assert_eq!(CryptoPolicyEngine::cache_size(), 0);
    }

    #[test]
    fn test_cache_hit() {
        CryptoPolicyEngine::clear_cache();

        let data = b"test data for cache hit";
        let char1 = CryptoPolicyEngine::analyze_data_characteristics(data);
        let char2 = CryptoPolicyEngine::analyze_data_characteristics(data);

        assert_eq!(char1.size, char2.size);
        assert_eq!(char1.entropy, char2.entropy);
        assert_eq!(char1.structure, char2.structure);
    }
}
