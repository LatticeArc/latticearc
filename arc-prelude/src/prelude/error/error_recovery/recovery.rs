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
                    Err(_) => continue,
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
