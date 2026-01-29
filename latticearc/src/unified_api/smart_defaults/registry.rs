#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Template registry for managing cryptographic templates

use std::collections::HashMap;

use super::templates::OptimizedTemplate;
use crate::unified_api::selector::UseCase;

/// Registry of optimized templates for different use cases
#[derive(Debug, Clone)]
pub struct TemplateRegistry {
    templates: HashMap<UseCase, OptimizedTemplate>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        let mut templates = HashMap::new();
        templates.insert(UseCase::Messaging, OptimizedTemplate::messaging_template());
        templates.insert(UseCase::Database, OptimizedTemplate::database_template());
        templates.insert(UseCase::MachineLearning, OptimizedTemplate::ml_template());
        templates.insert(
            UseCase::SecureAnalytics,
            OptimizedTemplate::secure_analytics_template(),
        );
        templates.insert(
            UseCase::HighSecurity,
            OptimizedTemplate::high_security_template(),
        );
        templates.insert(
            UseCase::PerformanceCritical,
            OptimizedTemplate::performance_template(),
        );
        templates.insert(
            UseCase::EncryptedMessagingE2E,
            OptimizedTemplate::encrypted_messaging_e2e_template(),
        );
        templates.insert(
            UseCase::FileStorage,
            OptimizedTemplate::file_storage_template(),
        );
        templates.insert(
            UseCase::RealTimeStream,
            OptimizedTemplate::real_time_stream_template(),
        );
        templates.insert(UseCase::IoTEdge, OptimizedTemplate::iot_edge_template());
        templates.insert(
            UseCase::MultiPartyComputation,
            OptimizedTemplate::multi_party_computation_template(),
        );
        templates.insert(
            UseCase::BlockchainWeb3,
            OptimizedTemplate::blockchain_web3_template(),
        );
        templates.insert(
            UseCase::HighThroughputBatch,
            OptimizedTemplate::high_throughput_batch_template(),
        );
        templates.insert(
            UseCase::SmallPayload,
            OptimizedTemplate::small_payload_template(),
        );

        Self { templates }
    }

    pub fn get_template(&self, use_case: UseCase) -> Option<&OptimizedTemplate> {
        self.templates.get(&use_case)
    }

    pub fn all_templates(&self) -> Vec<&OptimizedTemplate> {
        self.templates.values().collect()
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_registry() {
        let registry = TemplateRegistry::new();

        assert!(registry.get_template(UseCase::Messaging).is_some());
        assert!(registry.get_template(UseCase::Database).is_some());
        assert!(registry.get_template(UseCase::MachineLearning).is_some());

        let templates = registry.all_templates();
        assert!(!templates.is_empty());
    }

    #[test]
    fn test_all_new_templates_registered() {
        let registry = TemplateRegistry::new();

        assert!(registry.get_template(UseCase::EncryptedMessagingE2E).is_some());
        assert!(registry.get_template(UseCase::FileStorage).is_some());
        assert!(registry.get_template(UseCase::RealTimeStream).is_some());
        assert!(registry.get_template(UseCase::IoTEdge).is_some());
        assert!(registry.get_template(UseCase::MultiPartyComputation).is_some());
        assert!(registry.get_template(UseCase::BlockchainWeb3).is_some());
        assert!(registry.get_template(UseCase::HighThroughputBatch).is_some());
        assert!(registry.get_template(UseCase::SmallPayload).is_some());
    }
}
