//! Graceful Degradation Management
//!
//! This module handles graceful degradation of system functionality
//! when critical errors occur or resources become constrained.
//!
//! # Security Note
//!
//! All degradation events are MANDATORY logged for audit purposes.
//! Security degradation is a critical event that must be tracked.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use super::core::{EnhancedError, ErrorSeverity};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info, warn};

/// Information about service degradation
#[derive(Debug, Clone)]
pub struct ServiceDegradationInfo {
    /// Service name
    pub service: String,
    /// Degradation level (0.0 = normal, 1.0 = fully degraded)
    pub degradation_level: f64,
    /// Reason for degradation
    pub reason: String,
    /// Estimated recovery time
    pub estimated_recovery: Option<std::time::Duration>,
    /// Whether service is available
    pub available: bool,
}

/// Degradation strategy for handling reduced functionality
#[derive(Debug, Clone)]
pub struct DegradationStrategy {
    /// Strategy name
    pub name: String,
    /// Priority (higher = more important)
    pub priority: u8,
    /// Services to degrade
    pub services_to_degrade: Vec<String>,
    /// Minimum acceptable performance level
    pub min_performance_level: f64,
    /// Description of the strategy
    pub description: String,
}

/// Graceful degradation manager
pub struct GracefulDegradationManager {
    /// Current degradation state
    degraded_services: Arc<std::sync::Mutex<HashMap<String, ServiceDegradationInfo>>>,
    /// Available degradation strategies
    strategies: Vec<DegradationStrategy>,
    /// Whether degradation is active
    degradation_active: Arc<AtomicBool>,
    /// Performance monitoring
    performance_thresholds: HashMap<String, f64>,
}

impl GracefulDegradationManager {
    /// Create a new graceful degradation manager
    #[must_use]
    pub fn new() -> Self {
        let strategies = vec![
            DegradationStrategy {
                name: "reduce_precision".to_string(),
                priority: 1,
                services_to_degrade: vec!["encryption".to_string(), "hashing".to_string()],
                min_performance_level: 0.8,
                description: "Reduce cryptographic precision for better performance".to_string(),
            },
            DegradationStrategy {
                name: "disable_optional".to_string(),
                priority: 2,
                services_to_degrade: vec!["logging".to_string(), "metrics".to_string()],
                min_performance_level: 0.9,
                description: "Disable optional services to conserve resources".to_string(),
            },
            DegradationStrategy {
                name: "emergency_mode".to_string(),
                priority: 10,
                services_to_degrade: vec!["all".to_string()],
                min_performance_level: 0.5,
                description: "Emergency mode - minimal functionality only".to_string(),
            },
        ];

        Self {
            degraded_services: Arc::new(std::sync::Mutex::new(HashMap::new())),
            strategies,
            degradation_active: Arc::new(AtomicBool::new(false)),
            performance_thresholds: HashMap::new(),
        }
    }

    /// Handle a critical error by applying degradation strategies
    ///
    /// # Security Note
    /// All degradation decisions are logged for audit purposes.
    pub fn handle_critical_error(&self, error: &EnhancedError) {
        if error.severity < ErrorSeverity::High {
            return;
        }

        // SECURITY: Log critical error that triggered degradation evaluation
        warn!(
            error_component = %error.context.component,
            error_severity = ?error.severity,
            "Evaluating degradation strategies for critical error"
        );

        // Find appropriate strategy
        for strategy in &self.strategies {
            if Self::should_apply_strategy(strategy, error) {
                self.apply_degradation_strategy(strategy);
                break;
            }
        }
    }

    /// Check if a degradation strategy should be applied
    fn should_apply_strategy(strategy: &DegradationStrategy, error: &EnhancedError) -> bool {
        // Check if error affects services that this strategy handles
        let error_services = Self::extract_services_from_error(error);
        strategy
            .services_to_degrade
            .iter()
            .any(|service| error_services.contains(service) || service == "all")
    }

    /// Apply a degradation strategy
    ///
    /// # Security Note
    /// This function MUST log all degradation events for security audit.
    /// Security degradation is a critical event that could indicate attack or failure.
    fn apply_degradation_strategy(&self, strategy: &DegradationStrategy) {
        // SECURITY: MANDATORY logging for security degradation events
        // This is critical for compliance and incident response
        error!(
            strategy_name = %strategy.name,
            strategy_priority = strategy.priority,
            affected_services = ?strategy.services_to_degrade,
            min_performance_level = strategy.min_performance_level,
            "SECURITY DEGRADATION ACTIVATED - System operating in degraded security mode"
        );

        self.degradation_active.store(true, Ordering::SeqCst);

        let mut degraded = self.degraded_services.lock().unwrap_or_else(|e| {
            warn!("Degradation mutex was poisoned - recovering state");
            e.into_inner()
        });

        for service in &strategy.services_to_degrade {
            let info = ServiceDegradationInfo {
                service: service.clone(),
                degradation_level: 0.5, // Moderate degradation
                reason: format!("Applied strategy: {}", strategy.name),
                estimated_recovery: Some(std::time::Duration::from_secs(300)), // 5 minutes
                available: true, // Service still available but degraded
            };

            // Log each service being degraded
            warn!(
                service = %service,
                degradation_level = info.degradation_level,
                reason = %info.reason,
                "Service entering degraded mode"
            );

            degraded.insert(service.clone(), info);
        }
    }

    /// Check if a service is degraded
    #[must_use]
    pub fn is_service_degraded(&self, service: &str) -> bool {
        self.degraded_services
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(service)
    }

    /// Get degradation info for a service
    #[must_use]
    pub fn get_service_degradation_info(&self, service: &str) -> Option<ServiceDegradationInfo> {
        self.degraded_services
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(service)
            .cloned()
    }

    /// Get all degraded services
    #[must_use]
    pub fn get_all_degraded_services(&self) -> Vec<ServiceDegradationInfo> {
        self.degraded_services
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Attempt to recover degraded services
    pub fn attempt_recovery(&self) {
        if Self::should_recover() {
            self.perform_recovery();
        }
    }

    /// Check if recovery should be attempted
    fn should_recover() -> bool {
        false
    }

    /// Perform recovery of degraded services
    ///
    /// # Security Note
    /// Recovery events are also logged for audit trail completeness.
    fn perform_recovery(&self) {
        let mut degraded = self.degraded_services.lock().unwrap_or_else(|e| {
            warn!("Degradation mutex was poisoned during recovery - recovering state");
            e.into_inner()
        });

        // SECURITY: Log recovery event with details of services being restored
        let services_recovering: Vec<String> = degraded.keys().cloned().collect();
        info!(
            services = ?services_recovering,
            "SECURITY RECOVERY - Restoring services from degraded mode"
        );

        degraded.clear();
        self.degradation_active.store(false, Ordering::SeqCst);

        info!("Security degradation mode deactivated - full functionality restored");
    }

    /// Extract affected services from error
    fn extract_services_from_error(error: &EnhancedError) -> Vec<String> {
        vec![error.context.component.clone()]
    }

    /// Set performance threshold for a service
    pub fn set_performance_threshold(&mut self, service: String, threshold: f64) {
        self.performance_thresholds.insert(service, threshold);
    }

    /// Check if degradation is active
    #[must_use]
    pub fn is_degradation_active(&self) -> bool {
        self.degradation_active.load(Ordering::SeqCst)
    }
}

impl Default for GracefulDegradationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::core::{EnhancedError, ErrorContext, ErrorSeverity};
    use super::*;
    use crate::prelude::prelude::error::LatticeArcError;

    #[test]
    fn test_graceful_degradation_manager_new() {
        let manager = GracefulDegradationManager::new();
        assert!(!manager.is_degradation_active());
        assert!(manager.get_all_degraded_services().is_empty());
    }

    #[test]
    fn test_graceful_degradation_manager_default() {
        let manager = GracefulDegradationManager::default();
        assert!(!manager.is_degradation_active());
    }

    #[test]
    fn test_service_not_degraded_initially() {
        let manager = GracefulDegradationManager::new();
        assert!(!manager.is_service_degraded("encryption"));
        assert!(manager.get_service_degradation_info("encryption").is_none());
    }

    #[test]
    fn test_handle_critical_error_high_severity() {
        let manager = GracefulDegradationManager::new();

        let error = EnhancedError::new(
            LatticeArcError::EncryptionError("fatal".to_string()),
            "encrypt".to_string(),
        )
        .with_severity(ErrorSeverity::High)
        .with_context(ErrorContext::new().with_component("encryption".to_string()));

        manager.handle_critical_error(&error);

        // Should activate degradation for "encryption" component
        assert!(manager.is_degradation_active());
        assert!(manager.is_service_degraded("encryption"));
    }

    #[test]
    fn test_handle_critical_error_critical_severity() {
        let manager = GracefulDegradationManager::new();

        let error = EnhancedError::new(
            LatticeArcError::EncryptionError("catastrophic".to_string()),
            "encrypt".to_string(),
        )
        .with_severity(ErrorSeverity::Critical)
        .with_context(ErrorContext::new().with_component("encryption".to_string()));

        manager.handle_critical_error(&error);
        assert!(manager.is_degradation_active());
    }

    #[test]
    fn test_handle_critical_error_low_severity_ignored() {
        let manager = GracefulDegradationManager::new();

        let error = EnhancedError::new(
            LatticeArcError::InvalidInput("minor".to_string()),
            "parse".to_string(),
        )
        .with_severity(ErrorSeverity::Low)
        .with_context(ErrorContext::new().with_component("parser".to_string()));

        manager.handle_critical_error(&error);

        // Low severity should not trigger degradation
        assert!(!manager.is_degradation_active());
        assert!(!manager.is_service_degraded("parser"));
    }

    #[test]
    fn test_handle_critical_error_medium_severity_ignored() {
        let manager = GracefulDegradationManager::new();

        let error = EnhancedError::new(
            LatticeArcError::InvalidInput("moderate".to_string()),
            "op".to_string(),
        )
        .with_severity(ErrorSeverity::Medium)
        .with_context(ErrorContext::new().with_component("test".to_string()));

        manager.handle_critical_error(&error);
        assert!(!manager.is_degradation_active());
    }

    #[test]
    fn test_get_service_degradation_info() {
        let manager = GracefulDegradationManager::new();

        let error = EnhancedError::new(
            LatticeArcError::EncryptionError("fail".to_string()),
            "encrypt".to_string(),
        )
        .with_severity(ErrorSeverity::High)
        .with_context(ErrorContext::new().with_component("encryption".to_string()));

        manager.handle_critical_error(&error);

        let info = manager.get_service_degradation_info("encryption").unwrap();
        assert_eq!(info.service, "encryption");
        assert!((info.degradation_level - 0.5).abs() < f64::EPSILON);
        assert!(info.available);
        assert!(info.estimated_recovery.is_some());
        assert!(info.reason.contains("reduce_precision"));
    }

    #[test]
    fn test_get_all_degraded_services() {
        let manager = GracefulDegradationManager::new();

        let error = EnhancedError::new(
            LatticeArcError::EncryptionError("fail".to_string()),
            "encrypt".to_string(),
        )
        .with_severity(ErrorSeverity::High)
        .with_context(ErrorContext::new().with_component("encryption".to_string()));

        manager.handle_critical_error(&error);

        let services = manager.get_all_degraded_services();
        assert!(!services.is_empty());
    }

    #[test]
    fn test_attempt_recovery_when_not_needed() {
        let manager = GracefulDegradationManager::new();
        // should_recover returns false, so nothing happens
        manager.attempt_recovery();
        assert!(!manager.is_degradation_active());
    }

    #[test]
    fn test_set_performance_threshold() {
        let mut manager = GracefulDegradationManager::new();
        manager.set_performance_threshold("encryption".to_string(), 0.8);
        // Just verifies it doesn't panic - threshold stored internally
    }

    #[test]
    fn test_service_degradation_info_clone_and_debug() {
        let info = ServiceDegradationInfo {
            service: "test".to_string(),
            degradation_level: 0.5,
            reason: "testing".to_string(),
            estimated_recovery: Some(std::time::Duration::from_secs(60)),
            available: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.service, "test");
        assert!((cloned.degradation_level - 0.5).abs() < f64::EPSILON);
        assert!(cloned.available);

        let debug = format!("{:?}", info);
        assert!(debug.contains("ServiceDegradationInfo"));
    }

    #[test]
    fn test_degradation_strategy_clone_and_debug() {
        let strategy = DegradationStrategy {
            name: "test_strategy".to_string(),
            priority: 5,
            services_to_degrade: vec!["svc1".to_string()],
            min_performance_level: 0.7,
            description: "Test".to_string(),
        };
        let cloned = strategy.clone();
        assert_eq!(cloned.name, "test_strategy");
        assert_eq!(cloned.priority, 5);

        let debug = format!("{:?}", strategy);
        assert!(debug.contains("DegradationStrategy"));
    }

    #[test]
    fn test_all_strategy_matches_any_component() {
        let manager = GracefulDegradationManager::new();

        // Use a component that only matches "all" strategy (emergency_mode)
        // The first strategy "reduce_precision" handles "encryption" and "hashing"
        // "disable_optional" handles "logging" and "metrics"
        // "emergency_mode" handles "all"
        // A component like "custom_service" won't match reduce_precision or disable_optional
        // but WILL match emergency_mode's "all" wildcard
        let error = EnhancedError::new(
            LatticeArcError::EncryptionError("fail".to_string()),
            "op".to_string(),
        )
        .with_severity(ErrorSeverity::High)
        .with_context(ErrorContext::new().with_component("random_unknown_service".to_string()));

        manager.handle_critical_error(&error);

        // The emergency_mode strategy matches "all", so it should activate
        assert!(manager.is_degradation_active());
    }

    #[test]
    fn test_multiple_critical_errors() {
        let manager = GracefulDegradationManager::new();

        let error1 = EnhancedError::new(
            LatticeArcError::EncryptionError("fail".to_string()),
            "op1".to_string(),
        )
        .with_severity(ErrorSeverity::High)
        .with_context(ErrorContext::new().with_component("encryption".to_string()));

        let error2 = EnhancedError::new(
            LatticeArcError::EncryptionError("fail2".to_string()),
            "op2".to_string(),
        )
        .with_severity(ErrorSeverity::Critical)
        .with_context(ErrorContext::new().with_component("logging".to_string()));

        manager.handle_critical_error(&error1);
        manager.handle_critical_error(&error2);

        assert!(manager.is_degradation_active());
        let services = manager.get_all_degraded_services();
        assert!(services.len() >= 2);
    }
}
