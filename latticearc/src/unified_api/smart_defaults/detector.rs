#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Use case detection from data characteristics and context

use std::collections::HashMap;

use crate::unified_api::{
    error::CryptoError, selector::UseCase, DataCharacteristics, DataStructure,
};

/// Detector for inferring use cases from data and context
#[derive(Debug, Clone)]
pub struct UseCaseDetector {
    pattern_cache: HashMap<String, UseCase>,
}

impl UseCaseDetector {
    pub fn new() -> Result<Self, CryptoError> {
        let mut pattern_cache = HashMap::new();

        // Database patterns
        pattern_cache.insert("json".to_string(), UseCase::Database);
        pattern_cache.insert("sql".to_string(), UseCase::Database);
        pattern_cache.insert("db".to_string(), UseCase::Database);

        // Messaging patterns
        pattern_cache.insert("msg".to_string(), UseCase::Messaging);
        pattern_cache.insert("chat".to_string(), UseCase::Messaging);
        pattern_cache.insert("message".to_string(), UseCase::Messaging);

        // Machine learning patterns
        pattern_cache.insert("model".to_string(), UseCase::MachineLearning);
        pattern_cache.insert("ml".to_string(), UseCase::MachineLearning);
        pattern_cache.insert("ai".to_string(), UseCase::MachineLearning);
        pattern_cache.insert("train".to_string(), UseCase::MachineLearning);

        // Healthcare/Analytics patterns
        pattern_cache.insert("patient".to_string(), UseCase::SecureAnalytics);
        pattern_cache.insert("medical".to_string(), UseCase::SecureAnalytics);
        pattern_cache.insert("health".to_string(), UseCase::SecureAnalytics);
        pattern_cache.insert("phi".to_string(), UseCase::SecureAnalytics);

        // High security patterns
        pattern_cache.insert("transaction".to_string(), UseCase::HighSecurity);
        pattern_cache.insert("finance".to_string(), UseCase::HighSecurity);
        pattern_cache.insert("bank".to_string(), UseCase::HighSecurity);
        pattern_cache.insert("payment".to_string(), UseCase::HighSecurity);
        pattern_cache.insert("crypto".to_string(), UseCase::HighSecurity);

        // E2E encryption patterns
        pattern_cache.insert("e2e".to_string(), UseCase::EncryptedMessagingE2E);
        pattern_cache.insert("endtoend".to_string(), UseCase::EncryptedMessagingE2E);
        pattern_cache.insert("whatsapp".to_string(), UseCase::EncryptedMessagingE2E);
        pattern_cache.insert("signal".to_string(), UseCase::EncryptedMessagingE2E);

        // File storage patterns
        pattern_cache.insert("file".to_string(), UseCase::FileStorage);
        pattern_cache.insert("storage".to_string(), UseCase::FileStorage);
        pattern_cache.insert("s3".to_string(), UseCase::FileStorage);
        pattern_cache.insert("blob".to_string(), UseCase::FileStorage);
        pattern_cache.insert("cloud".to_string(), UseCase::FileStorage);

        // Real-time stream patterns
        pattern_cache.insert("stream".to_string(), UseCase::RealTimeStream);
        pattern_cache.insert("realtime".to_string(), UseCase::RealTimeStream);
        pattern_cache.insert("pipeline".to_string(), UseCase::RealTimeStream);
        pattern_cache.insert("kafka".to_string(), UseCase::RealTimeStream);

        // IoT/Edge patterns
        pattern_cache.insert("iot".to_string(), UseCase::IoTEdge);
        pattern_cache.insert("edge".to_string(), UseCase::IoTEdge);
        pattern_cache.insert("embedded".to_string(), UseCase::IoTEdge);
        pattern_cache.insert("sensor".to_string(), UseCase::IoTEdge);

        // Multi-party computation patterns
        pattern_cache.insert("mpc".to_string(), UseCase::MultiPartyComputation);
        pattern_cache.insert("multiparty".to_string(), UseCase::MultiPartyComputation);
        pattern_cache.insert("aggregation".to_string(), UseCase::MultiPartyComputation);

        // Blockchain/Web3 patterns
        pattern_cache.insert("blockchain".to_string(), UseCase::BlockchainWeb3);
        pattern_cache.insert("web3".to_string(), UseCase::BlockchainWeb3);
        pattern_cache.insert("smart".to_string(), UseCase::BlockchainWeb3);
        pattern_cache.insert("contract".to_string(), UseCase::BlockchainWeb3);

        // Batch processing patterns
        pattern_cache.insert("batch".to_string(), UseCase::HighThroughputBatch);
        pattern_cache.insert("spark".to_string(), UseCase::HighThroughputBatch);
        pattern_cache.insert("mapreduce".to_string(), UseCase::HighThroughputBatch);

        // Small payload patterns
        pattern_cache.insert("token".to_string(), UseCase::SmallPayload);
        pattern_cache.insert("jwt".to_string(), UseCase::SmallPayload);
        pattern_cache.insert("api".to_string(), UseCase::SmallPayload);
        pattern_cache.insert("small".to_string(), UseCase::SmallPayload);

        Ok(Self { pattern_cache })
    }

    pub fn detect_use_case(&self, data: &[u8]) -> Result<UseCase, CryptoError> {
        let characteristics = crate::unified_api::selector::CryptoPolicyEngine::analyze_data_characteristics(data);
        self.detect_from_characteristics(&characteristics)
    }

    pub fn detect_from_characteristics(
        &self,
        characteristics: &DataCharacteristics,
    ) -> Result<UseCase, CryptoError> {
        match characteristics.structure {
            DataStructure::Structured => Ok(UseCase::Database),
            DataStructure::Numeric => Ok(UseCase::SecureAnalytics),
            DataStructure::Text => Ok(UseCase::Messaging),
            DataStructure::Binary => {
                if characteristics.entropy > 7.5 {
                    Ok(UseCase::HighSecurity)
                } else {
                    Ok(UseCase::PerformanceCritical)
                }
            }
            DataStructure::Unstructured => Ok(UseCase::PerformanceCritical),
        }
    }

    pub fn detect_from_context(&self, context: &str) -> Result<UseCase, CryptoError> {
        let context_lower = context.to_lowercase();

        for (pattern, use_case) in &self.pattern_cache {
            if context_lower.contains(pattern) {
                return Ok(*use_case);
            }
        }

        Ok(UseCase::PerformanceCritical)
    }
}

impl Default for UseCaseDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create UseCaseDetector")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_use_case_detector_data() {
        let detector = UseCaseDetector::new().expect("Failed to create detector");

        let json_data = br#"{"key": "value"}"#;
        let use_case = detector.detect_use_case(json_data).expect("Detection failed");
        assert_eq!(use_case, UseCase::Database);

        let numeric_data = b"123.456";
        let use_case = detector.detect_use_case(numeric_data).expect("Detection failed");
        assert_eq!(use_case, UseCase::SecureAnalytics);

        let text_data = b"Hello, world!";
        let use_case = detector.detect_use_case(text_data).expect("Detection failed");
        assert_eq!(use_case, UseCase::Messaging);
    }

    #[test]
    fn test_use_case_detector_context() {
        let detector = UseCaseDetector::new().expect("Failed to create detector");

        let use_case = detector.detect_from_context("json_data").expect("Detection failed");
        assert_eq!(use_case, UseCase::Database);

        let use_case = detector.detect_from_context("chat_message").expect("Detection failed");
        assert_eq!(use_case, UseCase::Messaging);

        let use_case = detector.detect_from_context("ml_model").expect("Detection failed");
        assert_eq!(use_case, UseCase::MachineLearning);

        let use_case = detector.detect_from_context("patient_record").expect("Detection failed");
        assert_eq!(use_case, UseCase::SecureAnalytics);

        let use_case = detector.detect_from_context("transaction_log").expect("Detection failed");
        assert_eq!(use_case, UseCase::HighSecurity);
    }

    #[test]
    fn test_use_case_detector_new_patterns() {
        let detector = UseCaseDetector::new().expect("Failed to create detector");

        assert_eq!(
            detector.detect_from_context("e2e_encryption").expect("Failed"),
            UseCase::EncryptedMessagingE2E
        );
        assert_eq!(
            detector.detect_from_context("s3_bucket").expect("Failed"),
            UseCase::FileStorage
        );
        assert_eq!(
            detector.detect_from_context("stream_pipeline").expect("Failed"),
            UseCase::RealTimeStream
        );
        assert_eq!(
            detector.detect_from_context("iot_sensor").expect("Failed"),
            UseCase::IoTEdge
        );
        assert_eq!(
            detector.detect_from_context("mpc_protocol").expect("Failed"),
            UseCase::MultiPartyComputation
        );
        assert_eq!(
            detector.detect_from_context("blockchain_contract").expect("Failed"),
            UseCase::BlockchainWeb3
        );
        assert_eq!(
            detector.detect_from_context("batch_job").expect("Failed"),
            UseCase::HighThroughputBatch
        );
        assert_eq!(
            detector.detect_from_context("jwt_token").expect("Failed"),
            UseCase::SmallPayload
        );
    }
}
