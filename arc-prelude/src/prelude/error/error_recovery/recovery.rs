//! Error Recovery Handler
//!
//! This module provides the main error recovery handler that coordinates
//! different recovery strategies and monitors system health.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use super::core::{EnhancedError, ErrorSeverity, RecoveryStrategy};
use crate::prelude::error::Result;
use chrono::Utc;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// System health monitoring
#[derive(Debug, Clone)]
pub struct SystemHealth {
    /// Overall system health score (0.0 to 1.0)
    pub health_score: f64,
    /// Component health status
    pub component_health: HashMap<String, f64>,
    /// Recent error rate (errors per second)
    pub error_rate: f64,
    /// Recovery success rate
    pub recovery_success_rate: f64,
    /// Last health check time
    pub last_check: Instant,
    /// Health check interval
    pub check_interval: Duration,
    /// Recent error timestamps for accurate rate calculation
    pub error_timestamps: VecDeque<chrono::DateTime<Utc>>,
}

impl Default for SystemHealth {
    fn default() -> Self {
        Self {
            health_score: 1.0,
            component_health: HashMap::new(),
            error_rate: 0.0,
            recovery_success_rate: 1.0,
            last_check: Instant::now(),
            check_interval: Duration::from_secs(60),
            error_timestamps: VecDeque::new(),
        }
    }
}

impl SystemHealth {
    /// Check if system needs health assessment
    #[must_use]
    pub fn needs_check(&self) -> bool {
        self.last_check.elapsed() >= self.check_interval
    }

    /// Update component health
    pub fn update_component_health(&mut self, component: String, health: f64) {
        self.component_health.insert(component, health);
        self.recalculate_overall_health();
    }

    /// Record error occurrence
    #[allow(clippy::cast_precision_loss, clippy::arithmetic_side_effects)]
    pub fn record_error(&mut self) {
        let now = Utc::now();
        self.error_timestamps.push_back(now);

        // Remove errors older than the health check interval
        let window_start = now - self.check_interval;
        while let Some(&timestamp) = self.error_timestamps.front() {
            if timestamp < window_start {
                self.error_timestamps.pop_front();
            } else {
                break;
            }
        }

        // Calculate error rate as errors per second over the window
        let window_seconds = self.check_interval.as_secs_f64();
        self.error_rate = if window_seconds > 0.0 {
            (self.error_timestamps.len() as f64) / window_seconds
        } else {
            0.0
        }
        .min(1.0); // Cap at 1.0 to represent maximum error rate

        self.recalculate_overall_health();
    }

    /// Record successful recovery
    pub fn record_recovery_success(&mut self) {
        self.recovery_success_rate = (self.recovery_success_rate * 0.9 + 0.1).min(1.0);
        self.recalculate_overall_health();
    }

    /// Recalculate overall health score
    fn recalculate_overall_health(&mut self) {
        #[allow(clippy::cast_precision_loss)]
        let component_avg = if self.component_health.is_empty() {
            1.0
        } else {
            self.component_health.values().sum::<f64>() / self.component_health.len() as f64
        };

        let error_factor = 1.0 - self.error_rate;
        let recovery_factor = self.recovery_success_rate;

        self.health_score = (component_avg * 0.5) + (error_factor * 0.3) + (recovery_factor * 0.2);
        self.last_check = Instant::now();
    }

    /// Check if system is healthy
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.health_score >= 0.7
    }
}

/// Internal state for error recovery handler
struct ErrorRecoveryInternalState {
    system_health: SystemHealth,
    error_stats: ErrorStatistics,
}

/// Main error recovery handler
pub struct ErrorRecoveryHandler {
    /// Circuit breakers for different services
    circuit_breakers: HashMap<String, super::circuit_breaker::CircuitBreaker>,
    /// Recovery strategy registry
    recovery_strategies: HashMap<RecoveryStrategy, Box<dyn RecoveryStrategyImpl + Send + Sync>>,
    /// Graceful degradation manager
    degradation_manager: super::degradation::GracefulDegradationManager,
    /// Internal state with consolidated locks
    internal_state: Arc<Mutex<ErrorRecoveryInternalState>>,
}

impl ErrorRecoveryHandler {
    /// Create a new error recovery handler
    #[must_use]
    pub fn new() -> Self {
        let mut strategies = HashMap::new();

        // Register built-in strategies
        strategies.insert(
            RecoveryStrategy::Retry,
            Box::new(RetryStrategy::new()) as Box<dyn RecoveryStrategyImpl + Send + Sync>,
        );
        strategies.insert(
            RecoveryStrategy::Fallback,
            Box::new(FallbackStrategy::new()) as Box<dyn RecoveryStrategyImpl + Send + Sync>,
        );
        strategies.insert(
            RecoveryStrategy::CircuitBreaker,
            Box::new(CircuitBreakerStrategy::new()) as Box<dyn RecoveryStrategyImpl + Send + Sync>,
        );
        strategies.insert(
            RecoveryStrategy::GracefulDegradation,
            Box::new(GracefulDegradationStrategy::new())
                as Box<dyn RecoveryStrategyImpl + Send + Sync>,
        );

        Self {
            circuit_breakers: HashMap::new(),
            recovery_strategies: strategies,
            degradation_manager: super::degradation::GracefulDegradationManager::new(),
            internal_state: Arc::new(Mutex::new(ErrorRecoveryInternalState {
                system_health: SystemHealth::default(),
                error_stats: ErrorStatistics::new(),
            })),
        }
    }

    /// Handle an enhanced error
    ///
    /// # Errors
    /// Returns the original error if no recovery strategy succeeds.
    pub fn handle_error(&self, error: &EnhancedError) -> Result<()> {
        {
            let mut internal_state =
                self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            internal_state.error_stats.record_error(error);
            internal_state.system_health.record_error();
        }

        // Try recovery strategies in priority order
        for suggestion in &error.recovery_suggestions {
            if let Some(strategy) = self.recovery_strategies.get(&suggestion.strategy) {
                match strategy.attempt_recovery(error, suggestion) {
                    Ok(()) => {
                        self.internal_state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .system_health
                            .record_recovery_success();
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::debug!("Recovery strategy failed: {e}");
                        continue;
                    }
                }
            }
        }

        // If no recovery succeeded, check if graceful degradation is needed
        if error.severity >= ErrorSeverity::High {
            self.degradation_manager.handle_critical_error(error);
        }

        Err(error.error.clone())
    }

    /// Get circuit breaker for a service
    pub fn get_circuit_breaker(
        &mut self,
        service: &str,
    ) -> &mut super::circuit_breaker::CircuitBreaker {
        self.circuit_breakers.entry(service.to_string()).or_default()
    }

    /// Get system health status
    #[must_use]
    pub fn system_health(&self) -> SystemHealth {
        self.internal_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .system_health
            .clone()
    }

    /// Get error statistics
    #[must_use]
    pub fn error_stats(&self) -> ErrorStatistics {
        self.internal_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .error_stats
            .clone()
    }

    /// Force health check
    #[allow(clippy::arithmetic_side_effects)]
    pub fn force_health_check(&self) {
        let mut internal_state =
            self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        internal_state.system_health.last_check =
            Instant::now() - internal_state.system_health.check_interval;
    }
}

/// Error statistics tracking.
#[derive(Debug, Clone)]
pub struct ErrorStatistics {
    /// Total number of errors recorded.
    pub total_errors: usize,
    /// Error counts by severity level.
    pub errors_by_severity: HashMap<ErrorSeverity, usize>,
    /// Error counts by component name.
    pub errors_by_component: HashMap<String, usize>,
    /// Total number of recovery attempts.
    pub recovery_attempts: usize,
    /// Number of successful recoveries.
    pub successful_recoveries: usize,
    /// Timestamp of the last recorded error.
    pub last_error_time: Option<chrono::DateTime<Utc>>,
}

impl ErrorStatistics {
    fn new() -> Self {
        Self {
            total_errors: 0,
            errors_by_severity: HashMap::new(),
            errors_by_component: HashMap::new(),
            recovery_attempts: 0,
            successful_recoveries: 0,
            last_error_time: None,
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn record_error(&mut self, error: &EnhancedError) {
        self.total_errors += 1;
        *self.errors_by_severity.entry(error.severity).or_insert(0) += 1;
        *self.errors_by_component.entry(error.context.component.clone()).or_insert(0) += 1;
        self.last_error_time = Some(Utc::now());
    }

    /// Calculate the recovery success rate.
    ///
    /// Returns the ratio of successful recoveries to total recovery attempts.
    /// Returns 0.0 if no recovery attempts have been made.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn recovery_rate(&self) -> f64 {
        if self.recovery_attempts == 0 {
            0.0
        } else {
            self.successful_recoveries as f64 / self.recovery_attempts as f64
        }
    }
}

/// Recovery strategy trait
trait RecoveryStrategyImpl {
    fn attempt_recovery(
        &self,
        error: &EnhancedError,
        suggestion: &super::core::RecoverySuggestion,
    ) -> Result<()>;
}

/// Retry strategy implementation
struct RetryStrategy {
    _max_retries: usize,
}

impl RetryStrategy {
    fn new() -> Self {
        Self { _max_retries: 3 }
    }
}

impl RecoveryStrategyImpl for RetryStrategy {
    fn attempt_recovery(
        &self,
        error: &EnhancedError,
        _suggestion: &super::core::RecoverySuggestion,
    ) -> Result<()> {
        if Self::is_retryable(error) {
            // In a full implementation, this would retry the operation with exponential backoff
            // For now, indicate that retry is possible for transient errors
            Ok(())
        } else {
            Err(error.error.clone())
        }
    }
}

impl RetryStrategy {
    fn is_retryable(error: &EnhancedError) -> bool {
        matches!(
            &error.error,
            crate::prelude::error::LatticeArcError::NetworkError(_)
                | crate::prelude::error::LatticeArcError::TimeoutError(_)
                | crate::prelude::error::LatticeArcError::DatabaseError(_)
                | crate::prelude::error::LatticeArcError::ServiceUnavailable(_)
                | crate::prelude::error::LatticeArcError::CircuitBreakerOpen
        )
    }
}

/// Fallback strategy implementation
struct FallbackStrategy;

impl FallbackStrategy {
    fn new() -> Self {
        Self
    }
}

impl RecoveryStrategyImpl for FallbackStrategy {
    fn attempt_recovery(
        &self,
        error: &EnhancedError,
        _suggestion: &super::core::RecoverySuggestion,
    ) -> Result<()> {
        if Self::can_fallback(error) {
            // In a full implementation, this would switch to an alternative service or degraded mode
            // For now, indicate that fallback is possible for certain errors
            Ok(())
        } else {
            Err(error.error.clone())
        }
    }
}

impl FallbackStrategy {
    fn can_fallback(error: &EnhancedError) -> bool {
        matches!(
            &error.error,
            crate::prelude::error::LatticeArcError::ServiceUnavailable(_)
                | crate::prelude::error::LatticeArcError::NetworkError(_)
                | crate::prelude::error::LatticeArcError::HsmError(_)
        )
    }
}

/// Circuit breaker strategy
struct CircuitBreakerStrategy;

impl CircuitBreakerStrategy {
    fn new() -> Self {
        Self
    }
}

impl RecoveryStrategyImpl for CircuitBreakerStrategy {
    fn attempt_recovery(
        &self,
        _error: &EnhancedError,
        _suggestion: &super::core::RecoverySuggestion,
    ) -> Result<()> {
        // Circuit breaker logic would be implemented here
        Ok(())
    }
}

/// Graceful degradation strategy
struct GracefulDegradationStrategy;

impl GracefulDegradationStrategy {
    fn new() -> Self {
        Self
    }
}

impl RecoveryStrategyImpl for GracefulDegradationStrategy {
    fn attempt_recovery(
        &self,
        _error: &EnhancedError,
        _suggestion: &super::core::RecoverySuggestion,
    ) -> Result<()> {
        // Graceful degradation logic
        Ok(())
    }
}

impl Default for ErrorRecoveryHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::core::{
        EffortLevel, EnhancedError, ErrorContext, ErrorSeverity, RecoveryStrategy,
        RecoverySuggestion,
    };
    use super::*;
    use crate::prelude::error::LatticeArcError;

    // --- SystemHealth tests ---

    #[test]
    fn test_system_health_default() {
        let health = SystemHealth::default();
        assert!((health.health_score - 1.0).abs() < f64::EPSILON);
        assert!(health.component_health.is_empty());
        assert!((health.error_rate - 0.0).abs() < f64::EPSILON);
        assert!((health.recovery_success_rate - 1.0).abs() < f64::EPSILON);
        assert!(health.error_timestamps.is_empty());
        assert_eq!(health.check_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_system_health_is_healthy_default() {
        let health = SystemHealth::default();
        assert!(health.is_healthy());
    }

    #[test]
    fn test_system_health_needs_check_initially_false() {
        let health = SystemHealth::default();
        // Just created, shouldn't need check yet
        assert!(!health.needs_check());
    }

    #[test]
    fn test_system_health_update_component_health() {
        let mut health = SystemHealth::default();
        health.update_component_health("encryption".to_string(), 0.9);
        assert_eq!(health.component_health.get("encryption"), Some(&0.9));
        // health_score should be recalculated
        assert!(health.health_score > 0.0);
        assert!(health.health_score <= 1.0);
    }

    #[test]
    fn test_system_health_multiple_components() {
        let mut health = SystemHealth::default();
        health.update_component_health("encryption".to_string(), 1.0);
        health.update_component_health("hashing".to_string(), 0.5);
        // Component avg = 0.75, error_factor = 1.0, recovery = 1.0
        // Score = 0.75*0.5 + 1.0*0.3 + 1.0*0.2 = 0.375 + 0.3 + 0.2 = 0.875
        assert!((health.health_score - 0.875).abs() < 0.01);
    }

    #[test]
    fn test_system_health_record_error() {
        let mut health = SystemHealth::default();
        health.record_error();
        assert_eq!(health.error_timestamps.len(), 1);
        assert!(health.error_rate > 0.0);
    }

    #[test]
    fn test_system_health_record_multiple_errors() {
        let mut health = SystemHealth::default();
        for _ in 0..5 {
            health.record_error();
        }
        assert_eq!(health.error_timestamps.len(), 5);
        assert!(health.error_rate > 0.0);
    }

    #[test]
    fn test_system_health_record_recovery_success() {
        let mut health = SystemHealth::default();
        let initial_rate = health.recovery_success_rate;
        health.record_recovery_success();
        // recovery_success_rate = (1.0 * 0.9 + 0.1).min(1.0) = 1.0
        assert!((health.recovery_success_rate - initial_rate).abs() < 0.2);
    }

    #[test]
    fn test_system_health_low_health_not_healthy() {
        let mut health = SystemHealth::default();
        // Set very low component health
        health.update_component_health("critical".to_string(), 0.1);
        // Score drops well below 0.7
        // Component avg = 0.1, error_factor = 1.0, recovery = 1.0
        // Score = 0.1*0.5 + 1.0*0.3 + 1.0*0.2 = 0.05 + 0.3 + 0.2 = 0.55
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_system_health_clone_and_debug() {
        let health = SystemHealth::default();
        let cloned = health.clone();
        assert!((cloned.health_score - health.health_score).abs() < f64::EPSILON);
        let debug = format!("{:?}", health);
        assert!(debug.contains("SystemHealth"));
    }

    // --- ErrorStatistics tests ---

    #[test]
    fn test_error_statistics_new() {
        let stats = ErrorStatistics::new();
        assert_eq!(stats.total_errors, 0);
        assert!(stats.errors_by_severity.is_empty());
        assert!(stats.errors_by_component.is_empty());
        assert_eq!(stats.recovery_attempts, 0);
        assert_eq!(stats.successful_recoveries, 0);
        assert!(stats.last_error_time.is_none());
    }

    #[test]
    fn test_error_statistics_record_error() {
        let mut stats = ErrorStatistics::new();
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string())
            .with_severity(ErrorSeverity::High)
            .with_context(ErrorContext::new().with_component("crypto".to_string()));

        stats.record_error(&enhanced);
        assert_eq!(stats.total_errors, 1);
        assert_eq!(stats.errors_by_severity.get(&ErrorSeverity::High), Some(&1));
        assert_eq!(stats.errors_by_component.get("crypto"), Some(&1));
        assert!(stats.last_error_time.is_some());
    }

    #[test]
    fn test_error_statistics_multiple_errors() {
        let mut stats = ErrorStatistics::new();

        let e1 =
            EnhancedError::new(LatticeArcError::InvalidInput("a".to_string()), "op1".to_string())
                .with_severity(ErrorSeverity::High)
                .with_context(ErrorContext::new().with_component("crypto".to_string()));

        let e2 =
            EnhancedError::new(LatticeArcError::NetworkError("b".to_string()), "op2".to_string())
                .with_severity(ErrorSeverity::High)
                .with_context(ErrorContext::new().with_component("network".to_string()));

        let e3 =
            EnhancedError::new(LatticeArcError::InvalidInput("c".to_string()), "op3".to_string())
                .with_severity(ErrorSeverity::Low)
                .with_context(ErrorContext::new().with_component("crypto".to_string()));

        stats.record_error(&e1);
        stats.record_error(&e2);
        stats.record_error(&e3);

        assert_eq!(stats.total_errors, 3);
        assert_eq!(stats.errors_by_severity.get(&ErrorSeverity::High), Some(&2));
        assert_eq!(stats.errors_by_severity.get(&ErrorSeverity::Low), Some(&1));
        assert_eq!(stats.errors_by_component.get("crypto"), Some(&2));
        assert_eq!(stats.errors_by_component.get("network"), Some(&1));
    }

    #[test]
    fn test_error_statistics_recovery_rate_no_attempts() {
        let stats = ErrorStatistics::new();
        assert!((stats.recovery_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_error_statistics_recovery_rate_with_attempts() {
        let mut stats = ErrorStatistics::new();
        stats.recovery_attempts = 10;
        stats.successful_recoveries = 7;
        assert!((stats.recovery_rate() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_error_statistics_clone_and_debug() {
        let stats = ErrorStatistics::new();
        let cloned = stats.clone();
        assert_eq!(cloned.total_errors, 0);
        let debug = format!("{:?}", stats);
        assert!(debug.contains("ErrorStatistics"));
    }

    // --- ErrorRecoveryHandler tests ---

    #[test]
    fn test_error_recovery_handler_new() {
        let handler = ErrorRecoveryHandler::new();
        let health = handler.system_health();
        assert!(health.is_healthy());
    }

    #[test]
    fn test_error_recovery_handler_default() {
        let handler = ErrorRecoveryHandler::default();
        let health = handler.system_health();
        assert!(health.is_healthy());
    }

    #[test]
    fn test_error_recovery_handler_handle_retryable_error() {
        let handler = ErrorRecoveryHandler::new();
        let error = EnhancedError::new(
            LatticeArcError::NetworkError("timeout".to_string()),
            "connect".to_string(),
        )
        .with_recovery_suggestions(vec![RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "Retry".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.8,
            steps: vec!["Retry".to_string()],
        }]);

        // NetworkError is retryable, so recovery should succeed
        let result = handler.handle_error(&error);
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_recovery_handler_handle_non_retryable_error() {
        let handler = ErrorRecoveryHandler::new();
        let error = EnhancedError::new(
            LatticeArcError::InvalidInput("bad".to_string()),
            "parse".to_string(),
        )
        .with_recovery_suggestions(vec![RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "Retry".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.8,
            steps: vec!["Retry".to_string()],
        }]);

        // InvalidInput is NOT retryable via RetryStrategy
        let result = handler.handle_error(&error);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_recovery_handler_fallback_for_service_unavailable() {
        let handler = ErrorRecoveryHandler::new();
        let error = EnhancedError::new(
            LatticeArcError::ServiceUnavailable("down".to_string()),
            "call".to_string(),
        )
        .with_recovery_suggestions(vec![RecoverySuggestion {
            strategy: RecoveryStrategy::Fallback,
            description: "Fallback".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Medium,
            success_probability: 0.7,
            steps: vec!["Switch".to_string()],
        }]);

        let result = handler.handle_error(&error);
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_recovery_handler_circuit_breaker_strategy() {
        let handler = ErrorRecoveryHandler::new();
        let error =
            EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "op".to_string())
                .with_recovery_suggestions(vec![RecoverySuggestion {
                    strategy: RecoveryStrategy::CircuitBreaker,
                    description: "CB".to_string(),
                    priority: 8,
                    effort_estimate: EffortLevel::Medium,
                    success_probability: 0.9,
                    steps: vec!["Break".to_string()],
                }]);

        // CircuitBreakerStrategy always returns Ok
        let result = handler.handle_error(&error);
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_recovery_handler_graceful_degradation_strategy() {
        let handler = ErrorRecoveryHandler::new();
        let error =
            EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "op".to_string())
                .with_recovery_suggestions(vec![RecoverySuggestion {
                    strategy: RecoveryStrategy::GracefulDegradation,
                    description: "Degrade".to_string(),
                    priority: 5,
                    effort_estimate: EffortLevel::High,
                    success_probability: 0.6,
                    steps: vec!["Degrade".to_string()],
                }]);

        let result = handler.handle_error(&error);
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_recovery_handler_no_suggestions() {
        let handler = ErrorRecoveryHandler::new();
        let error =
            EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "op".to_string());
        // No recovery suggestions → returns error
        let result = handler.handle_error(&error);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_recovery_handler_high_severity_triggers_degradation() {
        let handler = ErrorRecoveryHandler::new();
        let error = EnhancedError::new(
            LatticeArcError::EncryptionError("fatal".to_string()),
            "encrypt".to_string(),
        )
        .with_severity(ErrorSeverity::Critical)
        .with_context(ErrorContext::new().with_component("encryption".to_string()));

        // No recovery suggestions, but high severity triggers degradation check
        let result = handler.handle_error(&error);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_recovery_handler_get_circuit_breaker() {
        let mut handler = ErrorRecoveryHandler::new();
        let cb = handler.get_circuit_breaker("database");
        let stats = cb.stats();
        assert_eq!(stats.state, super::super::circuit_breaker::CircuitBreakerState::Closed);
    }

    #[test]
    fn test_error_recovery_handler_error_stats() {
        let handler = ErrorRecoveryHandler::new();
        let stats = handler.error_stats();
        assert_eq!(stats.total_errors, 0);
    }

    #[test]
    fn test_error_recovery_handler_error_stats_after_handling() {
        let handler = ErrorRecoveryHandler::new();
        let error =
            EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "op".to_string())
                .with_severity(ErrorSeverity::Medium)
                .with_context(ErrorContext::new().with_component("test".to_string()));

        let _ = handler.handle_error(&error);
        let stats = handler.error_stats();
        assert_eq!(stats.total_errors, 1);
        assert_eq!(stats.errors_by_severity.get(&ErrorSeverity::Medium), Some(&1));
    }

    #[test]
    fn test_error_recovery_handler_force_health_check() {
        let handler = ErrorRecoveryHandler::new();
        handler.force_health_check();
        let health = handler.system_health();
        assert!(health.needs_check());
    }

    #[test]
    fn test_error_recovery_handler_health_degrades_with_errors() {
        let handler = ErrorRecoveryHandler::new();

        for i in 0..10 {
            let error = EnhancedError::new(
                LatticeArcError::InvalidInput(format!("err{i}")),
                "op".to_string(),
            )
            .with_severity(ErrorSeverity::Medium);
            let _ = handler.handle_error(&error);
        }

        let health = handler.system_health();
        // Health should decrease after many errors
        assert!(health.health_score < 1.0);
    }

    // --- Strategy-specific tests ---

    #[test]
    fn test_retry_strategy_retryable_errors() {
        let handler = ErrorRecoveryHandler::new();

        // Test all retryable error types
        let retryable_errors = vec![
            LatticeArcError::NetworkError("net".to_string()),
            LatticeArcError::TimeoutError("time".to_string()),
            LatticeArcError::DatabaseError("db".to_string()),
            LatticeArcError::ServiceUnavailable("svc".to_string()),
            LatticeArcError::CircuitBreakerOpen,
        ];

        for err in retryable_errors {
            let enhanced =
                EnhancedError::new(err, "op".to_string()).with_recovery_suggestions(vec![
                    RecoverySuggestion {
                        strategy: RecoveryStrategy::Retry,
                        description: "Retry".to_string(),
                        priority: 10,
                        effort_estimate: EffortLevel::Low,
                        success_probability: 0.8,
                        steps: vec!["Retry".to_string()],
                    },
                ]);

            assert!(handler.handle_error(&enhanced).is_ok(), "Expected retryable");
        }
    }

    #[test]
    fn test_fallback_strategy_fallbackable_errors() {
        let handler = ErrorRecoveryHandler::new();

        let fallbackable_errors = vec![
            LatticeArcError::ServiceUnavailable("svc".to_string()),
            LatticeArcError::NetworkError("net".to_string()),
            LatticeArcError::HsmError("hsm".to_string()),
        ];

        for err in fallbackable_errors {
            let enhanced =
                EnhancedError::new(err, "op".to_string()).with_recovery_suggestions(vec![
                    RecoverySuggestion {
                        strategy: RecoveryStrategy::Fallback,
                        description: "Fallback".to_string(),
                        priority: 10,
                        effort_estimate: EffortLevel::Medium,
                        success_probability: 0.7,
                        steps: vec!["Switch".to_string()],
                    },
                ]);

            assert!(handler.handle_error(&enhanced).is_ok(), "Expected fallbackable");
        }
    }

    #[test]
    fn test_fallback_strategy_non_fallbackable() {
        let handler = ErrorRecoveryHandler::new();
        let error =
            EnhancedError::new(LatticeArcError::InvalidInput("bad".to_string()), "op".to_string())
                .with_recovery_suggestions(vec![RecoverySuggestion {
                    strategy: RecoveryStrategy::Fallback,
                    description: "Fallback".to_string(),
                    priority: 10,
                    effort_estimate: EffortLevel::Medium,
                    success_probability: 0.7,
                    steps: vec!["Switch".to_string()],
                }]);

        // InvalidInput is NOT fallbackable
        let result = handler.handle_error(&error);
        assert!(result.is_err());
    }

    #[test]
    fn test_manual_intervention_strategy_not_registered() {
        let handler = ErrorRecoveryHandler::new();
        let error =
            EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "op".to_string())
                .with_recovery_suggestions(vec![RecoverySuggestion {
                    strategy: RecoveryStrategy::ManualIntervention,
                    description: "Manual".to_string(),
                    priority: 1,
                    effort_estimate: EffortLevel::VeryHigh,
                    success_probability: 0.3,
                    steps: vec!["Contact admin".to_string()],
                }]);

        // ManualIntervention is not registered as a strategy
        let result = handler.handle_error(&error);
        assert!(result.is_err());
    }
}
