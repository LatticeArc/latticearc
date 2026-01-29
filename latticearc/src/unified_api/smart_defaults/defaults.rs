#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Main smart defaults API for use-case-aware cryptographic parameter selection

use super::detector::UseCaseDetector;
use super::registry::TemplateRegistry;
use super::templates::OptimizedTemplate;
use crate::unified_api::{error::CryptoError, selector::UseCase};

/// Smart cryptographic defaults manager
///
/// Provides automatic selection of cryptographic parameters based on
/// data characteristics, use case context, and performance requirements.
#[derive(Debug, Clone)]
pub struct SmartDefaults {
    registry: TemplateRegistry,
    use_case_detector: UseCaseDetector,
}

impl SmartDefaults {
    pub fn new() -> Result<Self, CryptoError> {
        let registry = TemplateRegistry::new();
        let use_case_detector = UseCaseDetector::new()?;

        Ok(Self {
            registry,
            use_case_detector,
        })
    }

    /// Recommend a template based on data characteristics
    pub fn recommend_template(&self, data: &[u8]) -> Result<OptimizedTemplate, CryptoError> {
        let use_case = self.use_case_detector.detect_use_case(data)?;
        Ok(OptimizedTemplate::for_use_case(use_case))
    }

    /// Get a specific template for a use case
    pub fn get_template(&self, use_case: UseCase) -> Option<OptimizedTemplate> {
        self.registry.get_template(use_case).cloned()
    }

    /// Get all available templates
    pub fn all_templates(&self) -> Vec<OptimizedTemplate> {
        self.registry.all_templates().into_iter().cloned().collect()
    }

    /// Get a template based on context string
    pub fn get_template_for_context(
        &self,
        context: &str,
    ) -> Result<OptimizedTemplate, CryptoError> {
        let use_case = self.use_case_detector.detect_from_context(context)?;
        Ok(OptimizedTemplate::for_use_case(use_case))
    }
}

impl Default for SmartDefaults {
    fn default() -> Self {
        Self::new().expect("Failed to create SmartDefaults")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_defaults() {
        let smart_defaults = SmartDefaults::new().expect("Failed to create SmartDefaults");

        let json_data = br#"{"key": "value"}"#;
        let template = smart_defaults.recommend_template(json_data).expect("Failed");
        assert_eq!(template.use_case, UseCase::Database);

        let template = smart_defaults.get_template(UseCase::Messaging);
        assert!(template.is_some());
        assert_eq!(template.as_ref().map(|t| t.use_case), Some(UseCase::Messaging));

        let templates = smart_defaults.all_templates();
        assert!(!templates.is_empty());
    }

    #[test]
    fn test_smart_defaults_context() {
        let smart_defaults = SmartDefaults::new().expect("Failed to create SmartDefaults");

        let template = smart_defaults.get_template_for_context("ml_training_data").expect("Failed");
        assert_eq!(template.use_case, UseCase::MachineLearning);

        let template = smart_defaults.get_template_for_context("patient_phi").expect("Failed");
        assert_eq!(template.use_case, UseCase::SecureAnalytics);
    }
}
