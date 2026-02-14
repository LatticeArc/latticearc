//! Circuit Breaker for Protecting Against Cascading Failures
//!
//! This module implements the circuit breaker pattern to prevent
//! cascading failures when external services become unavailable.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::{LatticeArcError, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Circuit breaker state for external service failure protection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Circuit is closed - normal operation, requests flow through
    Closed,
    /// Circuit is open - service is failing, requests are rejected immediately
    Open,
    /// Circuit is half-open - testing if service has recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: usize,
    /// Success threshold to close circuit from half-open
    pub success_threshold: usize,
    /// Timeout before attempting recovery
    pub recovery_timeout: Duration,
    /// Monitoring window for failure counting
    pub monitoring_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            recovery_timeout: Duration::from_secs(60),
            monitoring_window: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Total number of requests
    pub total_requests: usize,
    /// Number of successful requests
    pub successful_requests: usize,
    /// Number of failed requests
    pub failed_requests: usize,
    /// Current state
    pub state: CircuitBreakerState,
    /// Time since last state change
    pub time_since_last_change: Duration,
}

/// Internal state for circuit breaker
struct CircuitBreakerInternalState {
    state: CircuitBreakerState,
    stats: CircuitBreakerStats,
    last_failure_time: Option<Instant>,
}

/// Circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    internal_state: Arc<Mutex<CircuitBreakerInternalState>>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default config
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom config
    #[must_use]
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            internal_state: Arc::new(Mutex::new(CircuitBreakerInternalState {
                state: CircuitBreakerState::Closed,
                stats: CircuitBreakerStats {
                    total_requests: 0,
                    successful_requests: 0,
                    failed_requests: 0,
                    state: CircuitBreakerState::Closed,
                    time_since_last_change: Duration::from_secs(0),
                },
                last_failure_time: None,
            })),
        }
    }

    /// Execute a function with circuit breaker protection
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    ///
    /// # Errors
    ///
    /// Returns `LatticeArcError::CircuitBreakerOpen` if the circuit breaker is open
    /// and not ready for recovery.
    pub fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let state =
            self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).state;
        match state {
            CircuitBreakerState::Open => {
                if self.should_attempt_reset() {
                    self.set_state(CircuitBreakerState::HalfOpen);
                    self.call_half_open(f)
                } else {
                    Err(LatticeArcError::CircuitBreakerOpen)
                }
            }
            CircuitBreakerState::HalfOpen => self.call_half_open(f),
            CircuitBreakerState::Closed => self.call_closed(f),
        }
    }

    fn call_closed<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let result = f();
        if result.is_ok() {
            self.record_success();
        } else {
            self.record_failure();
        }
        result
    }

    fn call_half_open<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let result = f();
        if result.is_ok() {
            self.record_success();
            self.set_state(CircuitBreakerState::Closed);
        } else {
            self.record_failure();
            self.set_state(CircuitBreakerState::Open);
        }
        result
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn record_success(&self) {
        let mut internal_state =
            self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        internal_state.stats.total_requests += 1;
        internal_state.stats.successful_requests += 1;
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn record_failure(&self) {
        let mut internal_state =
            self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        internal_state.stats.total_requests += 1;
        internal_state.stats.failed_requests += 1;
        internal_state.last_failure_time = Some(Instant::now());

        if internal_state.stats.failed_requests >= self.config.failure_threshold {
            internal_state.state = CircuitBreakerState::Open;
            internal_state.stats.state = CircuitBreakerState::Open;
            internal_state.stats.time_since_last_change = Duration::from_secs(0);
        }
    }

    fn should_attempt_reset(&self) -> bool {
        self.internal_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_failure_time
            .is_some_and(|last_failure| last_failure.elapsed() >= self.config.recovery_timeout)
    }

    fn set_state(&self, new_state: CircuitBreakerState) {
        let mut internal_state =
            self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        internal_state.state = new_state;
        internal_state.stats.state = new_state;
        internal_state.stats.time_since_last_change = Duration::from_secs(0);
    }

    /// Get current statistics
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn stats(&self) -> CircuitBreakerStats {
        self.internal_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).stats.clone()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_default_starts_closed() {
        let cb = CircuitBreaker::default();
        let stats = cb.stats();
        assert_eq!(stats.state, CircuitBreakerState::Closed);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_requests, 0);
        assert_eq!(stats.failed_requests, 0);
    }

    #[test]
    fn test_circuit_breaker_new_starts_closed() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
    }

    #[test]
    fn test_circuit_breaker_with_config() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            recovery_timeout: Duration::from_secs(30),
            monitoring_window: Duration::from_secs(120),
        };
        let cb = CircuitBreaker::with_config(config);
        assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
    }

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.success_threshold, 3);
        assert_eq!(config.recovery_timeout, Duration::from_secs(60));
        assert_eq!(config.monitoring_window, Duration::from_secs(300));
    }

    #[test]
    fn test_circuit_breaker_call_success() {
        let cb = CircuitBreaker::new();
        let result = cb.call(|| Ok(42));
        assert_eq!(result.unwrap(), 42);

        let stats = cb.stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.successful_requests, 1);
        assert_eq!(stats.failed_requests, 0);
    }

    #[test]
    fn test_circuit_breaker_call_failure() {
        let cb = CircuitBreaker::new();
        let result: Result<i32> =
            cb.call(|| Err(LatticeArcError::InvalidInput("fail".to_string())));
        assert!(result.is_err());

        let stats = cb.stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.failed_requests, 1);
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let config =
            CircuitBreakerConfig { failure_threshold: 3, ..CircuitBreakerConfig::default() };
        let cb = CircuitBreaker::with_config(config);

        for _ in 0..3 {
            let _: Result<i32> = cb.call(|| Err(LatticeArcError::InvalidInput("fail".to_string())));
        }

        assert_eq!(cb.stats().state, CircuitBreakerState::Open);
    }

    #[test]
    fn test_circuit_breaker_open_rejects_requests() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            recovery_timeout: Duration::from_secs(600), // Long timeout
            ..CircuitBreakerConfig::default()
        };
        let cb = CircuitBreaker::with_config(config);

        // Trip the circuit
        for _ in 0..2 {
            let _: Result<i32> = cb.call(|| Err(LatticeArcError::InvalidInput("fail".to_string())));
        }
        assert_eq!(cb.stats().state, CircuitBreakerState::Open);

        // Further calls should be rejected
        let result: Result<i32> = cb.call(|| Ok(42));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LatticeArcError::CircuitBreakerOpen));
    }

    #[test]
    fn test_circuit_breaker_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            recovery_timeout: Duration::from_millis(1), // Very short timeout
            ..CircuitBreakerConfig::default()
        };
        let cb = CircuitBreaker::with_config(config);

        // Trip the circuit
        for _ in 0..2 {
            let _: Result<i32> = cb.call(|| Err(LatticeArcError::InvalidInput("fail".to_string())));
        }
        assert_eq!(cb.stats().state, CircuitBreakerState::Open);

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(5));

        // Next call should transition to half-open and succeed
        let result = cb.call(|| Ok(42));
        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_failure_reopens() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            recovery_timeout: Duration::from_millis(1),
            ..CircuitBreakerConfig::default()
        };
        let cb = CircuitBreaker::with_config(config);

        // Trip the circuit
        for _ in 0..2 {
            let _: Result<i32> = cb.call(|| Err(LatticeArcError::InvalidInput("fail".to_string())));
        }

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(5));

        // Failure in half-open should reopen
        let _: Result<i32> =
            cb.call(|| Err(LatticeArcError::InvalidInput("still failing".to_string())));
        assert_eq!(cb.stats().state, CircuitBreakerState::Open);
    }

    #[test]
    fn test_circuit_breaker_stats_tracking() {
        let config =
            CircuitBreakerConfig { failure_threshold: 10, ..CircuitBreakerConfig::default() };
        let cb = CircuitBreaker::with_config(config);

        for _ in 0..3 {
            let _ = cb.call(|| Ok::<_, LatticeArcError>(()));
        }
        for _ in 0..2 {
            let _: Result<()> = cb.call(|| Err(LatticeArcError::InvalidInput("fail".to_string())));
        }

        let stats = cb.stats();
        assert_eq!(stats.total_requests, 5);
        assert_eq!(stats.successful_requests, 3);
        assert_eq!(stats.failed_requests, 2);
    }

    #[test]
    fn test_circuit_breaker_state_enum() {
        assert_eq!(CircuitBreakerState::Closed, CircuitBreakerState::Closed);
        assert_ne!(CircuitBreakerState::Open, CircuitBreakerState::Closed);
        assert_ne!(CircuitBreakerState::HalfOpen, CircuitBreakerState::Open);

        let debug = format!("{:?}", CircuitBreakerState::HalfOpen);
        assert!(debug.contains("HalfOpen"));
    }

    #[test]
    fn test_circuit_breaker_stats_clone_debug() {
        let cb = CircuitBreaker::new();
        let _ = cb.call(|| Ok::<_, LatticeArcError>(()));
        let stats = cb.stats();
        let cloned = stats.clone();
        assert_eq!(cloned.total_requests, stats.total_requests);

        let debug = format!("{:?}", stats);
        assert!(debug.contains("CircuitBreakerStats"));
    }

    #[test]
    fn test_circuit_breaker_config_clone_debug() {
        let config = CircuitBreakerConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.failure_threshold, config.failure_threshold);

        let debug = format!("{:?}", config);
        assert!(debug.contains("CircuitBreakerConfig"));
    }
}
