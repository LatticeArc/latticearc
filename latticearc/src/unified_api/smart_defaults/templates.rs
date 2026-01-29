#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Optimized cryptographic templates for different use cases

use std::collections::HashMap;

use super::params::AlgorithmParams;
use super::types::MlKemVariant;
use crate::unified_api::{
    config::CryptoConfig,
    phi_masking::PhiMaskingEngine,
    selector::UseCase,
    types::{
        ClassicalScheme, CryptoScheme, HardwarePreference, HomomorphicScheme,
        PerformancePreference, SecurityLevel,
    },
};

/// Optimized template for a specific use case
#[derive(Debug, Clone)]
pub struct OptimizedTemplate {
    pub name: &'static str,
    pub use_case: UseCase,
    pub scheme: CryptoScheme,
    pub security_level: SecurityLevel,
    pub performance: PerformancePreference,
    pub key_size: usize,
    pub algorithm_params: AlgorithmParams,
    pub hardware_preference: HardwarePreference,
}

impl OptimizedTemplate {
    pub fn for_use_case(use_case: UseCase) -> Self {
        match use_case {
            UseCase::Messaging => Self::messaging_template(),
            UseCase::Database => Self::database_template(),
            UseCase::MachineLearning => Self::ml_template(),
            UseCase::SecureAnalytics => Self::secure_analytics_template(),
            UseCase::HighSecurity => Self::high_security_template(),
            UseCase::PerformanceCritical => Self::performance_template(),
            UseCase::EncryptedMessagingE2E => Self::encrypted_messaging_e2e_template(),
            UseCase::FileStorage => Self::file_storage_template(),
            UseCase::RealTimeStream => Self::real_time_stream_template(),
            UseCase::IoTEdge => Self::iot_edge_template(),
            UseCase::MultiPartyComputation => Self::multi_party_computation_template(),
            UseCase::BlockchainWeb3 => Self::blockchain_web3_template(),
            UseCase::HighThroughputBatch => Self::high_throughput_batch_template(),
            UseCase::SmallPayload => Self::small_payload_template(),
            _ => Self::general_purpose_template(),
        }
    }

    pub fn messaging_template() -> Self {
        Self {
            name: "Messaging/Communication",
            use_case: UseCase::Messaging,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Speed,
            key_size: 32,
            algorithm_params: AlgorithmParams::hybrid_messaging(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn database_template() -> Self {
        Self {
            name: "Database/Storage",
            use_case: UseCase::Database,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::hybrid_database(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn ml_template() -> Self {
        Self {
            name: "Machine Learning",
            use_case: UseCase::MachineLearning,
            scheme: CryptoScheme::Homomorphic(HomomorphicScheme::CKKS),
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::ml_fhe(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn secure_analytics_template() -> Self {
        Self {
            name: "Secure Analytics (Healthcare)",
            use_case: UseCase::SecureAnalytics,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::High,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::healthcare(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn healthcare_template() -> Self {
        Self {
            name: "Healthcare (HIPAA Compliant)",
            use_case: UseCase::SecureAnalytics,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::High,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::healthcare(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn financial_template() -> Self {
        Self {
            name: "Financial Services",
            use_case: UseCase::HighSecurity,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Maximum,
            performance: PerformancePreference::Balanced,
            key_size: 48,
            algorithm_params: AlgorithmParams::financial(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn high_security_template() -> Self {
        Self {
            name: "High Security (Post-Quantum Only)",
            use_case: UseCase::HighSecurity,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Maximum,
            performance: PerformancePreference::Balanced,
            key_size: 48,
            algorithm_params: AlgorithmParams::high_security(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn performance_template() -> Self {
        Self {
            name: "Maximum Performance",
            use_case: UseCase::PerformanceCritical,
            scheme: CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305),
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Speed,
            key_size: 32,
            algorithm_params: AlgorithmParams::performance(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn general_purpose_template() -> Self {
        Self {
            name: "General Purpose (Balanced)",
            use_case: UseCase::PerformanceCritical,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::general_purpose(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn encrypted_messaging_e2e_template() -> Self {
        Self {
            name: "Encrypted Messaging (E2E)",
            use_case: UseCase::EncryptedMessagingE2E,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::High,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::encrypted_messaging_e2e(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn file_storage_template() -> Self {
        Self {
            name: "File Storage/Cloud Storage",
            use_case: UseCase::FileStorage,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::High,
            performance: PerformancePreference::Throughput,
            key_size: 32,
            algorithm_params: AlgorithmParams::file_storage(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn real_time_stream_template() -> Self {
        Self {
            name: "Real-Time Stream Processing",
            use_case: UseCase::RealTimeStream,
            scheme: CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305),
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Latency,
            key_size: 32,
            algorithm_params: AlgorithmParams::real_time_stream(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn iot_edge_template() -> Self {
        Self {
            name: "IoT/Edge Devices",
            use_case: UseCase::IoTEdge,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Memory,
            key_size: 16,
            algorithm_params: AlgorithmParams::iot_edge(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn multi_party_computation_template() -> Self {
        Self {
            name: "Multi-Party Computation",
            use_case: UseCase::MultiPartyComputation,
            scheme: CryptoScheme::MultiParty(crate::unified_api::types::MpcScheme::FROST),
            security_level: SecurityLevel::High,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::multi_party_computation(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn blockchain_web3_template() -> Self {
        Self {
            name: "Blockchain/Web3",
            use_case: UseCase::BlockchainWeb3,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Maximum,
            performance: PerformancePreference::Balanced,
            key_size: 32,
            algorithm_params: AlgorithmParams::blockchain_web3(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn high_throughput_batch_template() -> Self {
        Self {
            name: "High-Throughput Batch Processing",
            use_case: UseCase::HighThroughputBatch,
            scheme: CryptoScheme::Classical(ClassicalScheme::Aes256Gcm),
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Throughput,
            key_size: 32,
            algorithm_params: AlgorithmParams::high_throughput_batch(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    pub fn small_payload_template() -> Self {
        Self {
            name: "Small Payload Optimization",
            use_case: UseCase::SmallPayload,
            scheme: CryptoScheme::HybridPq,
            security_level: SecurityLevel::Standard,
            performance: PerformancePreference::Speed,
            key_size: 16,
            algorithm_params: AlgorithmParams::small_payload(),
            hardware_preference: HardwarePreference::Auto,
        }
    }

    /// Create a PHI masking engine for healthcare templates
    pub fn phi_masking_engine(&self) -> Option<PhiMaskingEngine> {
        match self.use_case {
            UseCase::SecureAnalytics => Some(PhiMaskingEngine::new()),
            _ => None,
        }
    }

    pub fn to_crypto_config(&self) -> CryptoConfig {
        CryptoConfig {
            security_level: self.security_level,
            performance_preference: self.performance,
            hardware_preference: self.hardware_preference,
            use_hardware_acceleration: true,
            preferred_schemes: vec![self.scheme],
            custom_parameters: HashMap::new(),
            enable_compression: false,
            enable_serialization: true,
            cache_keys: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_messaging_template() {
        let template = OptimizedTemplate::messaging_template();
        assert_eq!(template.use_case, UseCase::Messaging);
        assert_eq!(template.security_level, SecurityLevel::Standard);
        assert_eq!(template.performance, PerformancePreference::Speed);
    }

    #[test]
    fn test_database_template() {
        let template = OptimizedTemplate::database_template();
        assert_eq!(template.use_case, UseCase::Database);
        assert_eq!(template.security_level, SecurityLevel::Standard);
        assert_eq!(template.performance, PerformancePreference::Balanced);
    }

    #[test]
    fn test_ml_template() {
        let template = OptimizedTemplate::ml_template();
        assert_eq!(template.use_case, UseCase::MachineLearning);
        assert!(matches!(
            template.scheme,
            CryptoScheme::Homomorphic(HomomorphicScheme::CKKS)
        ));
        assert!(template.algorithm_params.fhe_params.is_some());
    }

    #[test]
    fn test_healthcare_template() {
        let template = OptimizedTemplate::healthcare_template();
        assert_eq!(template.use_case, UseCase::SecureAnalytics);
        assert_eq!(template.security_level, SecurityLevel::High);
    }

    #[test]
    fn test_financial_template() {
        let template = OptimizedTemplate::financial_template();
        assert_eq!(template.use_case, UseCase::HighSecurity);
        assert_eq!(template.security_level, SecurityLevel::Maximum);
        assert_eq!(template.key_size, 48);
    }

    #[test]
    fn test_high_security_template() {
        let template = OptimizedTemplate::high_security_template();
        assert_eq!(template.use_case, UseCase::HighSecurity);
        assert_eq!(template.security_level, SecurityLevel::Maximum);
        assert_eq!(template.key_size, 48);
    }

    #[test]
    fn test_performance_template() {
        let template = OptimizedTemplate::performance_template();
        assert_eq!(template.use_case, UseCase::PerformanceCritical);
        assert_eq!(template.performance, PerformancePreference::Speed);
        assert!(matches!(
            template.scheme,
            CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
        ));
    }

    #[test]
    fn test_general_purpose_template() {
        let template = OptimizedTemplate::general_purpose_template();
        assert_eq!(template.use_case, UseCase::PerformanceCritical);
        assert_eq!(template.security_level, SecurityLevel::Standard);
        assert_eq!(template.performance, PerformancePreference::Balanced);
    }

    #[test]
    fn test_encrypted_messaging_e2e_template() {
        let template = OptimizedTemplate::encrypted_messaging_e2e_template();
        assert_eq!(template.use_case, UseCase::EncryptedMessagingE2E);
        assert_eq!(template.security_level, SecurityLevel::High);
        assert_eq!(template.performance, PerformancePreference::Balanced);
    }

    #[test]
    fn test_file_storage_template() {
        let template = OptimizedTemplate::file_storage_template();
        assert_eq!(template.use_case, UseCase::FileStorage);
        assert_eq!(template.security_level, SecurityLevel::High);
        assert_eq!(template.performance, PerformancePreference::Throughput);
    }

    #[test]
    fn test_real_time_stream_template() {
        let template = OptimizedTemplate::real_time_stream_template();
        assert_eq!(template.use_case, UseCase::RealTimeStream);
        assert_eq!(template.security_level, SecurityLevel::Standard);
        assert_eq!(template.performance, PerformancePreference::Latency);
        assert!(matches!(
            template.scheme,
            CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305)
        ));
    }

    #[test]
    fn test_iot_edge_template() {
        let template = OptimizedTemplate::iot_edge_template();
        assert_eq!(template.use_case, UseCase::IoTEdge);
        assert_eq!(template.key_size, 16);
        assert_eq!(template.performance, PerformancePreference::Memory);
        assert!(matches!(
            template.algorithm_params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem512
        ));
    }

    #[test]
    fn test_multi_party_computation_template() {
        let template = OptimizedTemplate::multi_party_computation_template();
        assert_eq!(template.use_case, UseCase::MultiPartyComputation);
        assert_eq!(template.security_level, SecurityLevel::High);
        assert!(matches!(
            template.scheme,
            CryptoScheme::MultiParty(crate::unified_api::types::MpcScheme::FROST)
        ));
    }

    #[test]
    fn test_blockchain_web3_template() {
        let template = OptimizedTemplate::blockchain_web3_template();
        assert_eq!(template.use_case, UseCase::BlockchainWeb3);
        assert_eq!(template.security_level, SecurityLevel::Maximum);
        assert_eq!(template.performance, PerformancePreference::Balanced);
    }

    #[test]
    fn test_high_throughput_batch_template() {
        let template = OptimizedTemplate::high_throughput_batch_template();
        assert_eq!(template.use_case, UseCase::HighThroughputBatch);
        assert_eq!(template.performance, PerformancePreference::Throughput);
        assert!(matches!(
            template.scheme,
            CryptoScheme::Classical(ClassicalScheme::Aes256Gcm)
        ));
    }

    #[test]
    fn test_small_payload_template() {
        let template = OptimizedTemplate::small_payload_template();
        assert_eq!(template.use_case, UseCase::SmallPayload);
        assert_eq!(template.key_size, 16);
        assert_eq!(template.performance, PerformancePreference::Speed);
        assert!(matches!(
            template.algorithm_params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem512
        ));
    }

    #[test]
    fn test_template_to_crypto_config() {
        let template = OptimizedTemplate::messaging_template();
        let config = template.to_crypto_config();

        assert_eq!(config.security_level, template.security_level);
        assert_eq!(config.performance_preference, template.performance);
        assert_eq!(config.hardware_preference, template.hardware_preference);
        assert_eq!(config.preferred_schemes, vec![template.scheme]);
    }
}
