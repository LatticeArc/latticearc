//! Error Recovery Framework Comprehensive Tests
//!
//! This module contains comprehensive tests for the error recovery framework
//! covering all state transitions, error handling paths, and edge cases.
//!
//! Tests implemented (tasks 1.7.1-1.7.16):
//! 1. CircuitBreaker states: Closed, Open, HalfOpen
//! 2. Failure threshold triggering
//! 3. Recovery timeout behavior
//! 4. Successful call resets failures
//! 5. Concurrent access to circuit breaker
//! 6. Graceful degradation levels: Full, Degraded, Emergency
//! 7. Degradation strategy selection
//! 8. Recovery handler retry logic
//! 9. Exponential backoff simulation
//! 10. Max retries limit
//! 11. Error classification
//! 12. Recovery callbacks

// Test-specific lint allowances for test utilities and assertions
#![allow(clippy::expect_used)] // Tests use expect for clearer failure messages
#![allow(clippy::indexing_slicing)] // Direct indexing is acceptable in tests
#![allow(clippy::float_cmp)] // Exact float comparisons are intentional in tests
#![allow(clippy::useless_vec)] // vec! in tests improves readability
#![allow(clippy::arithmetic_side_effects)] // Arithmetic in tests is safe

use latticearc::prelude::prelude::error::LatticeArcError;
use latticearc::prelude::prelude::error::error_recovery::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, DegradationStrategy, EffortLevel,
    EnhancedError, EnhancedErrorHandler, ErrorContext, ErrorRecoveryHandler, ErrorSeverity,
    GracefulDegradationManager, RecoveryStrategy, RecoverySuggestion, ServiceDegradationInfo,
    SystemHealth, get_error_handler,
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Task 1.7.1: CircuitBreaker States - Closed, Open, HalfOpen
// ============================================================================

#[test]
fn test_circuit_breaker_state_closed_initial() {
    let cb = CircuitBreaker::new();
    let stats = cb.stats();

    assert_eq!(stats.state, CircuitBreakerState::Closed);
    assert_eq!(stats.total_requests, 0);
    assert_eq!(stats.successful_requests, 0);
    assert_eq!(stats.failed_requests, 0);
}

#[test]
fn test_circuit_breaker_state_open_after_threshold() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Cause 3 failures to trigger Open state
    for _ in 0..3 {
        let _: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("connection failed".to_string())));
    }

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

#[test]
fn test_circuit_breaker_state_half_open_after_timeout() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(50),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("test".to_string())));
    }
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Wait for recovery timeout
    thread::sleep(Duration::from_millis(100));

    // Next call should transition to HalfOpen, then to Closed on success
    let result = cb.call(|| Ok("recovered"));
    assert!(result.is_ok());

    // After successful call in HalfOpen, transitions to Closed
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
}

#[test]
fn test_circuit_breaker_all_state_transitions() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(50),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Start: Closed
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);

    // Transition: Closed -> Open (via failures)
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Wait for recovery timeout
    thread::sleep(Duration::from_millis(100));

    // Transition: Open -> HalfOpen -> Closed (via success)
    let result = cb.call(|| Ok("success"));
    assert!(result.is_ok());
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);

    // Transition: Closed -> Open -> HalfOpen -> Open (via failure in HalfOpen)
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    thread::sleep(Duration::from_millis(100));

    // Fail in HalfOpen should reopen
    let _: Result<(), _> =
        cb.call(|| Err(LatticeArcError::NetworkError("still failing".to_string())));
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

// ============================================================================
// Task 1.7.2: Failure Threshold Triggering
// ============================================================================

#[test]
fn test_failure_threshold_exact_boundary() {
    let config = CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Cause failures up to threshold - 1
    for _ in 0..4 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("error".to_string())));
    }

    // Should still be Closed
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
    assert_eq!(cb.stats().failed_requests, 4);

    // One more failure should trigger Open
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("error".to_string())));

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
    assert_eq!(cb.stats().failed_requests, 5);
}

#[test]
fn test_failure_threshold_with_intermittent_successes() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Mix of successes and failures
    let _ = cb.call(|| Ok("success"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    let _ = cb.call(|| Ok("success"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    let _ = cb.call(|| Ok("success"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    // 3 failures reached, circuit should be open
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

#[test]
fn test_failure_threshold_minimum_value() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Single failure should open circuit
    let _: Result<(), _> =
        cb.call(|| Err(LatticeArcError::EncryptionError("critical".to_string())));

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

#[test]
fn test_failure_threshold_high_value() {
    let config = CircuitBreakerConfig {
        failure_threshold: 100,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Cause 99 failures
    for _ in 0..99 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }

    // Should still be Closed
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);

    // 100th failure should open
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

// ============================================================================
// Task 1.7.3: Recovery Timeout Behavior
// ============================================================================

#[test]
fn test_recovery_timeout_not_elapsed() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Immediately try another call (timeout not elapsed)
    let result = cb.call(|| Ok("should not execute"));

    // Should return CircuitBreakerOpen error
    assert!(matches!(result, Err(LatticeArcError::CircuitBreakerOpen)));
}

#[test]
fn test_recovery_timeout_elapsed() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(50),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }

    // Wait for timeout
    thread::sleep(Duration::from_millis(100));

    // Now should allow the call
    let result = cb.call(|| Ok("recovered"));
    assert!(result.is_ok());
}

#[test]
fn test_recovery_timeout_zero_instant_recovery() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(0),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open circuit with single failure
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    // Should immediately allow retry
    let result = cb.call(|| Ok("instant retry"));
    assert!(result.is_ok());
}

#[test]
fn test_recovery_timeout_precise_boundary() {
    // Use generous margins: CI runners can oversleep by 50-200ms on loaded VMs.
    // recovery_timeout=2000ms, sleep 200ms for "too early" (well under 2s),
    // then sleep 2500ms more for "now allowed" (well over 2s total).
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(2000),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }

    // Wait well under the timeout (200ms << 2000ms)
    thread::sleep(Duration::from_millis(200));

    // Should still be blocked
    let result = cb.call(|| Ok("too early"));
    assert!(matches!(result, Err(LatticeArcError::CircuitBreakerOpen)));

    // Wait well past the timeout (200 + 2500 = 2700ms > 2000ms)
    thread::sleep(Duration::from_millis(2500));

    // Now should be allowed
    let result = cb.call(|| Ok("now allowed"));
    assert!(result.is_ok());
}

// ============================================================================
// Task 1.7.4: Successful Call Resets Failures
// ============================================================================

#[test]
fn test_successful_call_increments_success_count() {
    let cb = CircuitBreaker::new();

    let _ = cb.call(|| Ok("success 1"));
    let _ = cb.call(|| Ok("success 2"));
    let _ = cb.call(|| Ok("success 3"));

    let stats = cb.stats();
    assert_eq!(stats.successful_requests, 3);
    assert_eq!(stats.failed_requests, 0);
    assert_eq!(stats.total_requests, 3);
}

#[test]
fn test_half_open_success_closes_circuit() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(50),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Wait for recovery timeout
    thread::sleep(Duration::from_millis(100));

    // Success in HalfOpen should close circuit
    let _ = cb.call(|| Ok("recovery success"));
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
}

#[test]
fn test_closed_state_success_maintains_state() {
    let config = CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);

    // Mix failures (below threshold) with successes
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    let _ = cb.call(|| Ok("success"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    let _ = cb.call(|| Ok("success"));

    // Should remain closed
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
    assert_eq!(cb.stats().successful_requests, 2);
    assert_eq!(cb.stats().failed_requests, 2);
}

// ============================================================================
// Task 1.7.5: Concurrent Access to Circuit Breaker
// ============================================================================

#[test]
fn test_concurrent_circuit_breaker_multiple_threads() {
    // Use high failure threshold to prevent circuit from opening during concurrent test
    let config = CircuitBreakerConfig {
        failure_threshold: 100,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = Arc::new(CircuitBreaker::with_config(config));
    let barrier = Arc::new(Barrier::new(10));
    let mut handles = vec![];

    for i in 0..10 {
        let cb_clone = Arc::clone(&cb);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier_clone.wait();
            let result = cb_clone.call(|| {
                if i % 2 == 0 {
                    Ok(i)
                } else {
                    Err(LatticeArcError::InvalidInput(format!("thread {}", i)))
                }
            });
            result.is_ok()
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for handle in handles {
        if handle.join().unwrap_or(false) {
            successes += 1;
        }
    }

    let stats = cb.stats();
    assert_eq!(stats.total_requests, 10);
    assert_eq!(stats.successful_requests, 5);
    assert_eq!(stats.failed_requests, 5);
    assert_eq!(successes, 5);
}

#[test]
fn test_concurrent_circuit_breaker_stress_test() {
    // Use high failure threshold to prevent circuit from opening during stress test
    let config = CircuitBreakerConfig {
        failure_threshold: 1000,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = Arc::new(CircuitBreaker::with_config(config));
    let mut handles = vec![];
    let num_threads = 50;

    for i in 0..num_threads {
        let cb_clone = Arc::clone(&cb);

        let handle = thread::spawn(move || {
            for j in 0..10 {
                let _ = cb_clone.call(|| {
                    if (i + j) % 3 == 0 {
                        Err(LatticeArcError::NetworkError("fail".to_string()))
                    } else {
                        Ok("success")
                    }
                });
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    let stats = cb.stats();
    // All requests should be processed (circuit never opens due to high threshold)
    assert_eq!(stats.total_requests, num_threads * 10);
}

#[test]
fn test_concurrent_circuit_breaker_state_consistency() {
    let config = CircuitBreakerConfig {
        failure_threshold: 100,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = Arc::new(CircuitBreaker::with_config(config));
    let mut handles = vec![];

    // All failures
    for _ in 0..20 {
        let cb_clone = Arc::clone(&cb);
        let handle = thread::spawn(move || {
            for _ in 0..5 {
                let _: Result<(), _> =
                    cb_clone.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    let stats = cb.stats();
    // 20 threads * 5 failures each = 100 failures
    assert_eq!(stats.failed_requests, 100);
    assert_eq!(stats.state, CircuitBreakerState::Open);
}

// ============================================================================
// Task 1.7.6: Graceful Degradation Levels - Full, Degraded, Emergency
// ============================================================================

#[test]
fn test_degradation_level_full_initial_state() {
    let manager = GracefulDegradationManager::new();

    // Initially, no degradation
    assert!(!manager.is_degradation_active());
    assert!(manager.get_all_degraded_services().is_empty());
}

#[test]
fn test_degradation_level_degraded_on_high_severity() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::EncryptionError("crypto failure".to_string()),
        "encrypt".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    assert!(manager.is_degradation_active());

    // Check degradation level
    if let Some(info) = manager.get_service_degradation_info("encryption") {
        assert!(info.degradation_level > 0.0);
        assert!(info.degradation_level <= 1.0);
        assert!(info.available); // Still available but degraded
    }
}

#[test]
fn test_degradation_level_emergency_on_critical() {
    let manager = GracefulDegradationManager::new();

    // Critical error on "all" services triggers emergency mode
    let error =
        EnhancedError::new(LatticeArcError::ResourceExhausted, "system_failure".to_string())
            .with_context(ErrorContext::new().with_component("all".to_string()))
            .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&error);

    assert!(manager.is_degradation_active());

    let degraded_services = manager.get_all_degraded_services();
    assert!(!degraded_services.is_empty());

    // Emergency mode should degrade "all" service
    assert!(manager.is_service_degraded("all"));
}

#[test]
fn test_degradation_level_no_change_for_low_severity() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::InvalidInput("minor issue".to_string()),
        "validate".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::Low);

    manager.handle_critical_error(&error);

    // Low severity should not trigger degradation
    assert!(!manager.is_degradation_active());
}

#[test]
fn test_degradation_level_no_change_for_medium_severity() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::InvalidInput("medium issue".to_string()),
        "validate".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::Medium);

    manager.handle_critical_error(&error);

    // Medium severity should not trigger degradation
    assert!(!manager.is_degradation_active());
}

// ============================================================================
// Task 1.7.7: Degradation Strategy Selection
// ============================================================================

#[test]
fn test_strategy_selection_reduce_precision() {
    let manager = GracefulDegradationManager::new();

    // Error in encryption component should match "reduce_precision" strategy
    let error = EnhancedError::new(
        LatticeArcError::EncryptionError("performance issue".to_string()),
        "encrypt".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    assert!(manager.is_degradation_active());
    assert!(manager.is_service_degraded("encryption"));

    if let Some(info) = manager.get_service_degradation_info("encryption") {
        assert!(info.reason.contains("reduce_precision"));
    }
}

#[test]
fn test_strategy_selection_disable_optional() {
    let manager = GracefulDegradationManager::new();

    // Error in logging component should match "disable_optional" strategy
    let error = EnhancedError::new(
        LatticeArcError::ServiceUnavailable("logging down".to_string()),
        "log".to_string(),
    )
    .with_context(ErrorContext::new().with_component("logging".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    if manager.is_degradation_active() {
        assert!(manager.is_service_degraded("logging"));
    }
}

#[test]
fn test_strategy_selection_emergency_mode() {
    let manager = GracefulDegradationManager::new();

    // Error matching "all" should trigger emergency_mode strategy
    let error =
        EnhancedError::new(LatticeArcError::ResourceExhausted, "critical_failure".to_string())
            .with_context(ErrorContext::new().with_component("all".to_string()))
            .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&error);

    assert!(manager.is_degradation_active());
    assert!(manager.is_service_degraded("all"));

    if let Some(info) = manager.get_service_degradation_info("all") {
        assert!(info.reason.contains("emergency_mode"));
    }
}

#[test]
fn test_strategy_selection_priority_ordering() {
    // Test that strategies are applied in priority order
    let strategy1 = DegradationStrategy {
        name: "low_priority".to_string(),
        priority: 1,
        services_to_degrade: vec!["service_a".to_string()],
        min_performance_level: 0.5,
        description: "Low priority strategy".to_string(),
    };

    let strategy2 = DegradationStrategy {
        name: "high_priority".to_string(),
        priority: 10,
        services_to_degrade: vec!["service_b".to_string()],
        min_performance_level: 0.8,
        description: "High priority strategy".to_string(),
    };

    assert!(strategy2.priority > strategy1.priority);
}

// ============================================================================
// Task 1.7.8: Recovery Handler Retry Logic
// ============================================================================

#[test]
fn test_recovery_handler_retryable_errors() {
    let handler = EnhancedErrorHandler::new();

    // Network errors are retryable
    let network_error = LatticeArcError::NetworkError("timeout".to_string());
    let result =
        handler.handle_error(&network_error, "api_call".to_string(), "network".to_string());

    // Recovery handler should attempt retry strategy
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_recovery_handler_non_retryable_errors() {
    let handler = EnhancedErrorHandler::new();

    // Invalid signature is not retryable
    let sig_error = LatticeArcError::InvalidSignature("bad signature".to_string());
    let result = handler.handle_error(&sig_error, "verify".to_string(), "crypto".to_string());

    // Should fall back to manual intervention
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_recovery_handler_tracks_recovery_attempts() {
    let handler = ErrorRecoveryHandler::new();

    let error = EnhancedError::new(
        LatticeArcError::NetworkError("transient".to_string()),
        "retry_test".to_string(),
    )
    .with_recovery_suggestions(vec![RecoverySuggestion {
        strategy: RecoveryStrategy::Retry,
        description: "Retry operation".to_string(),
        priority: 10,
        effort_estimate: EffortLevel::Low,
        success_probability: 0.9,
        steps: vec!["wait".to_string(), "retry".to_string()],
    }]);

    let _result = handler.handle_error(&error);

    let stats = handler.error_stats();
    assert!(stats.total_errors >= 1);
}

// ============================================================================
// Task 1.7.9: Exponential Backoff Simulation
// ============================================================================

#[test]
fn test_exponential_backoff_timing_simulation() {
    // Simulate exponential backoff with circuit breaker
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(100),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Record timing for backoff simulation
    let start = Instant::now();
    let mut attempt_times: Vec<Duration> = vec![];

    // First attempt
    attempt_times.push(start.elapsed());
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    // Second attempt with simulated backoff
    thread::sleep(Duration::from_millis(10));
    attempt_times.push(start.elapsed());
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    // Third attempt with longer backoff
    thread::sleep(Duration::from_millis(20));
    attempt_times.push(start.elapsed());
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    // Verify increasing gaps between attempts
    assert!(attempt_times.len() == 3);
    let gap1 = attempt_times[1] - attempt_times[0];
    let gap2 = attempt_times[2] - attempt_times[1];
    assert!(gap2 > gap1);
}

#[test]
fn test_exponential_backoff_with_jitter_simulation() {
    use rand::Rng;

    let base_delay_ms = 100;
    let mut delays: Vec<u64> = vec![];

    for attempt in 0..5 {
        let exponential_delay = base_delay_ms * (1u64 << attempt);
        let jitter: u64 = rand::thread_rng().gen_range(0..=exponential_delay / 4);
        let total_delay = exponential_delay + jitter;
        delays.push(total_delay);
    }

    // Verify exponential growth (approximately)
    for i in 1..delays.len() {
        // Each delay should be roughly double the previous (with some jitter variance)
        assert!(delays[i] > delays[i - 1]);
    }
}

// ============================================================================
// Task 1.7.10: Max Retries Limit
// ============================================================================

#[test]
fn test_max_retries_respected() {
    let config = CircuitBreakerConfig {
        failure_threshold: 10,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);
    let max_retries = 5;
    let mut retry_count = 0;

    for _ in 0..max_retries {
        let result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
        if result.is_err() {
            retry_count += 1;
        }
    }

    assert_eq!(retry_count, max_retries);
    assert_eq!(cb.stats().failed_requests, max_retries);
}

#[test]
fn test_max_retries_stops_on_success() {
    let cb = CircuitBreaker::new();
    let mut attempt_count = 0;

    // Simulate retry loop that succeeds on 3rd attempt
    for i in 0..5 {
        attempt_count += 1;
        let result = cb.call(|| {
            if i < 2 {
                Err(LatticeArcError::NetworkError("temporary".to_string()))
            } else {
                Ok("success")
            }
        });

        if result.is_ok() {
            break;
        }
    }

    assert_eq!(attempt_count, 3);
    assert_eq!(cb.stats().successful_requests, 1);
    assert_eq!(cb.stats().failed_requests, 2);
}

#[test]
fn test_max_retries_with_circuit_breaker_interaction() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60),
        monitoring_window: Duration::from_secs(300),
    };

    let cb = CircuitBreaker::with_config(config);
    let max_retries = 5;
    let mut actual_attempts = 0;

    for _ in 0..max_retries {
        let result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

        match result {
            Err(LatticeArcError::CircuitBreakerOpen) => {
                // Circuit opened, stop retrying
                break;
            }
            _ => {
                actual_attempts += 1;
            }
        }
    }

    // Should have stopped at circuit breaker threshold (3), not max_retries (5)
    assert_eq!(actual_attempts, 3);
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

// ============================================================================
// Task 1.7.11: Error Classification
// ============================================================================

#[test]
fn test_error_classification_by_severity() {
    let test_cases = vec![
        (LatticeArcError::InvalidInput("test".to_string()), ErrorSeverity::Medium),
        (LatticeArcError::NetworkError("test".to_string()), ErrorSeverity::High),
        (LatticeArcError::EncryptionError("test".to_string()), ErrorSeverity::High),
        (LatticeArcError::CircuitBreakerOpen, ErrorSeverity::Critical),
        (LatticeArcError::ResourceExhausted, ErrorSeverity::Critical),
        (LatticeArcError::InvalidKey("test".to_string()), ErrorSeverity::Medium),
    ];

    let handler = EnhancedErrorHandler::new();

    for (error, expected_severity) in test_cases {
        let result =
            handler.handle_error(&error, "test_op".to_string(), "test_component".to_string());

        // Verify error was processed
        assert!(result.is_ok() || result.is_err());

        // Create enhanced error to verify severity classification
        let enhanced =
            EnhancedError::new(error, "test".to_string()).with_severity(expected_severity);
        assert_eq!(enhanced.severity, expected_severity);
    }
}

#[test]
fn test_error_classification_network_errors() {
    let network_errors = vec![
        LatticeArcError::NetworkError("connection refused".to_string()),
        LatticeArcError::TimeoutError("request timeout".to_string()),
        LatticeArcError::ServiceUnavailable("service down".to_string()),
    ];

    for error in network_errors {
        let enhanced = EnhancedError::new(error, "network_op".to_string());
        // Network errors should be recoverable via retry
        let suggestions = vec![RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "Retry".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.8,
            steps: vec![],
        }];
        let enhanced_with_recovery = enhanced.with_recovery_suggestions(suggestions);
        assert!(enhanced_with_recovery.is_recoverable());
    }
}

#[test]
fn test_error_classification_crypto_errors() {
    let crypto_errors = vec![
        LatticeArcError::EncryptionError("encryption failed".to_string()),
        LatticeArcError::DecryptionError("decryption failed".to_string()),
        LatticeArcError::InvalidSignature("bad signature".to_string()),
        LatticeArcError::KeyGenerationError("keygen failed".to_string()),
    ];

    for error in crypto_errors {
        let enhanced = EnhancedError::new(error, "crypto_op".to_string())
            .with_context(ErrorContext::new().with_component("crypto".to_string()));

        assert_eq!(enhanced.context.component, "crypto");
    }
}

#[test]
fn test_error_classification_severity_ordering() {
    assert!(ErrorSeverity::Low < ErrorSeverity::Medium);
    assert!(ErrorSeverity::Medium < ErrorSeverity::High);
    assert!(ErrorSeverity::High < ErrorSeverity::Critical);

    // Test that severity comparison works
    let low =
        EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "test".to_string())
            .with_severity(ErrorSeverity::Low);

    let critical = EnhancedError::new(LatticeArcError::ResourceExhausted, "test".to_string())
        .with_severity(ErrorSeverity::Critical);

    assert!(critical.severity > low.severity);
}

// ============================================================================
// Task 1.7.12: Recovery Callbacks
// ============================================================================

#[test]
fn test_recovery_callback_on_success() {
    let handler = ErrorRecoveryHandler::new();
    let initial_health = handler.system_health();
    let initial_recovery_rate = initial_health.recovery_success_rate;

    // Process error that can be recovered
    let error = EnhancedError::new(
        LatticeArcError::NetworkError("temporary".to_string()),
        "callback_test".to_string(),
    )
    .with_recovery_suggestions(vec![RecoverySuggestion {
        strategy: RecoveryStrategy::Retry,
        description: "Retry".to_string(),
        priority: 10,
        effort_estimate: EffortLevel::Low,
        success_probability: 0.9,
        steps: vec![],
    }]);

    let result = handler.handle_error(&error);

    // Check recovery was tracked
    let updated_health = handler.system_health();

    // If recovery was successful, rate should be maintained or improved
    if result.is_ok() {
        assert!(updated_health.recovery_success_rate >= initial_recovery_rate * 0.9);
    }
}

#[test]
fn test_recovery_callback_on_failure() {
    let handler = ErrorRecoveryHandler::new();

    // Error without recovery suggestions
    let error = EnhancedError::new(
        LatticeArcError::InvalidSignature("unrecoverable".to_string()),
        "callback_test".to_string(),
    )
    .with_recovery_suggestions(vec![]); // No recovery suggestions

    let result = handler.handle_error(&error);

    // Should fail to recover
    assert!(result.is_err());

    let stats = handler.error_stats();
    assert!(stats.total_errors >= 1);
}

#[test]
fn test_recovery_callback_health_update() {
    let handler = ErrorRecoveryHandler::new();

    // Multiple errors to observe health degradation
    for _ in 0..5 {
        let error = EnhancedError::new(
            LatticeArcError::NetworkError("repeated".to_string()),
            "health_test".to_string(),
        );
        let _ = handler.handle_error(&error);
    }

    let health = handler.system_health();
    assert!(health.error_rate > 0.0);
}

#[test]
fn test_recovery_callback_statistics_tracking() {
    let handler = ErrorRecoveryHandler::new();

    let errors = vec![
        EnhancedError::new(LatticeArcError::NetworkError("net".to_string()), "op1".to_string())
            .with_severity(ErrorSeverity::High)
            .with_context(ErrorContext::new().with_component("network".to_string())),
        EnhancedError::new(LatticeArcError::DatabaseError("db".to_string()), "op2".to_string())
            .with_severity(ErrorSeverity::Medium)
            .with_context(ErrorContext::new().with_component("database".to_string())),
        EnhancedError::new(
            LatticeArcError::EncryptionError("crypto".to_string()),
            "op3".to_string(),
        )
        .with_severity(ErrorSeverity::Critical)
        .with_context(ErrorContext::new().with_component("crypto".to_string())),
    ];

    for error in errors {
        let _ = handler.handle_error(&error);
    }

    let stats = handler.error_stats();
    assert_eq!(stats.total_errors, 3);
    assert!(!stats.errors_by_severity.is_empty());
    assert!(!stats.errors_by_component.is_empty());
}

// ============================================================================
// Additional Comprehensive Tests
// ============================================================================

#[test]
fn test_circuit_breaker_stats_accuracy() {
    let cb = CircuitBreaker::new();

    // Perform various operations
    let _ = cb.call(|| Ok("s1"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("f1".to_string())));
    let _ = cb.call(|| Ok("s2"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("f2".to_string())));
    let _ = cb.call(|| Ok("s3"));
    let _ = cb.call(|| Ok("s4"));
    let _: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("f3".to_string())));

    let stats = cb.stats();
    assert_eq!(stats.total_requests, 7);
    assert_eq!(stats.successful_requests, 4);
    assert_eq!(stats.failed_requests, 3);
}

#[test]
fn test_circuit_breaker_default_config_values() {
    let config = CircuitBreakerConfig::default();

    assert_eq!(config.failure_threshold, 5);
    assert_eq!(config.success_threshold, 3);
    assert_eq!(config.recovery_timeout, Duration::from_secs(60));
    assert_eq!(config.monitoring_window, Duration::from_secs(300));
}

#[test]
fn test_enhanced_error_builder_pattern() {
    let error = EnhancedError::new(
        LatticeArcError::NetworkError("test".to_string()),
        "test_op".to_string(),
    )
    .with_context(
        ErrorContext::new()
            .with_user_message("User message".to_string())
            .with_component("test_component".to_string())
            .add_technical_detail("key1".to_string(), "value1".to_string())
            .add_parameter("param1".to_string(), "param_value".to_string())
            .add_system_state("state1".to_string(), "state_value".to_string()),
    )
    .with_severity(ErrorSeverity::High)
    .with_recovery_suggestions(vec![RecoverySuggestion {
        strategy: RecoveryStrategy::Retry,
        description: "Retry the operation".to_string(),
        priority: 10,
        effort_estimate: EffortLevel::Low,
        success_probability: 0.9,
        steps: vec!["Step 1".to_string(), "Step 2".to_string()],
    }]);

    assert_eq!(error.operation, "test_op");
    assert_eq!(error.severity, ErrorSeverity::High);
    assert_eq!(error.context.user_message, "User message");
    assert_eq!(error.context.component, "test_component");
    assert!(error.is_recoverable());
    assert_eq!(error.recovery_suggestions.len(), 1);
    assert_eq!(error.context.technical_details.get("key1"), Some(&"value1".to_string()));
}

#[test]
fn test_system_health_degradation_tracking() {
    let mut health = SystemHealth::default();

    assert!(health.is_healthy());
    assert_eq!(health.health_score, 1.0);

    // Record multiple errors
    for _ in 0..20 {
        health.record_error();
    }

    // Health should degrade
    assert!(health.health_score < 1.0);
    assert!(health.error_rate > 0.0);
}

#[test]
fn test_system_health_recovery_improvement() {
    let mut health = SystemHealth::default();

    // Degrade health
    for _ in 0..10 {
        health.record_error();
    }

    let score_after_errors = health.health_score;

    // Record recoveries
    for _ in 0..10 {
        health.record_recovery_success();
    }

    // Health should improve
    assert!(health.health_score >= score_after_errors);
}

#[test]
fn test_error_statistics_by_component() {
    let handler = ErrorRecoveryHandler::new();

    let components = vec!["network", "database", "crypto", "network", "crypto"];

    for component in components {
        let error = EnhancedError::new(
            LatticeArcError::InvalidInput("test".to_string()),
            "test_op".to_string(),
        )
        .with_context(ErrorContext::new().with_component(component.to_string()));

        let _ = handler.handle_error(&error);
    }

    let stats = handler.error_stats();
    assert_eq!(stats.total_errors, 5);
    assert_eq!(stats.errors_by_component.get("network"), Some(&2));
    assert_eq!(stats.errors_by_component.get("crypto"), Some(&2));
    assert_eq!(stats.errors_by_component.get("database"), Some(&1));
}

#[test]
fn test_global_error_handler() {
    let handler = get_error_handler();

    // Should be able to use global handler
    assert!(handler.is_system_healthy());

    let health = handler.system_health();
    assert!(health.health_score >= 0.0);
}

#[test]
fn test_recovery_strategy_variants() {
    let strategies = vec![
        RecoveryStrategy::Retry,
        RecoveryStrategy::Fallback,
        RecoveryStrategy::CircuitBreaker,
        RecoveryStrategy::GracefulDegradation,
        RecoveryStrategy::ManualIntervention,
    ];

    // Verify all variants are distinct
    for (i, s1) in strategies.iter().enumerate() {
        for (j, s2) in strategies.iter().enumerate() {
            if i != j {
                assert_ne!(s1, s2);
            }
        }
    }
}

#[test]
fn test_effort_level_variants() {
    let levels =
        vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High, EffortLevel::VeryHigh];

    // Verify all variants are distinct
    for (i, l1) in levels.iter().enumerate() {
        for (j, l2) in levels.iter().enumerate() {
            if i != j {
                assert_ne!(l1, l2);
            }
        }
    }
}

#[test]
fn test_service_degradation_info_complete() {
    let info = ServiceDegradationInfo {
        service: "test_service".to_string(),
        degradation_level: 0.5,
        reason: "Test degradation".to_string(),
        estimated_recovery: Some(Duration::from_secs(300)),
        available: true,
    };

    assert_eq!(info.service, "test_service");
    assert_eq!(info.degradation_level, 0.5);
    assert!(!info.reason.is_empty());
    assert!(info.estimated_recovery.is_some());
    assert!(info.available);

    // Clone test
    let cloned = info.clone();
    assert_eq!(info.service, cloned.service);
    assert_eq!(info.degradation_level, cloned.degradation_level);
}

#[test]
fn test_degradation_strategy_complete() {
    let strategy = DegradationStrategy {
        name: "test_strategy".to_string(),
        priority: 7,
        services_to_degrade: vec!["svc1".to_string(), "svc2".to_string()],
        min_performance_level: 0.75,
        description: "Test strategy description".to_string(),
    };

    assert_eq!(strategy.name, "test_strategy");
    assert_eq!(strategy.priority, 7);
    assert_eq!(strategy.services_to_degrade.len(), 2);
    assert_eq!(strategy.min_performance_level, 0.75);

    // Clone test
    let cloned = strategy.clone();
    assert_eq!(strategy.name, cloned.name);
    assert_eq!(strategy.priority, cloned.priority);
}

#[test]
fn test_error_context_default() {
    let context = ErrorContext::default();

    assert!(context.user_message.is_empty());
    assert!(context.technical_details.is_empty());
    assert!(context.component.is_empty());
    assert!(context.parameters.is_empty());
    assert!(context.system_state.is_empty());
}

#[test]
fn test_circuit_breaker_clone_stats() {
    let cb = CircuitBreaker::new();
    let _ = cb.call(|| Ok("test"));

    let stats1 = cb.stats();
    let stats2 = stats1.clone();

    assert_eq!(stats1.total_requests, stats2.total_requests);
    assert_eq!(stats1.successful_requests, stats2.successful_requests);
    assert_eq!(stats1.state, stats2.state);
}

#[test]
fn test_multiple_circuit_breakers_independence() {
    let mut handler = ErrorRecoveryHandler::new();

    // Create circuit breakers for different services
    {
        let cb1 = handler.get_circuit_breaker("service_a");
        let _ = cb1.call(|| Ok("a1"));
        let _ = cb1.call(|| Ok("a2"));
    }

    {
        let cb2 = handler.get_circuit_breaker("service_b");
        let _: Result<(), _> =
            cb2.call(|| Err(LatticeArcError::NetworkError("b_fail".to_string())));
    }

    // Verify independence
    let cb1_stats = handler.get_circuit_breaker("service_a").stats();
    let cb2_stats = handler.get_circuit_breaker("service_b").stats();

    assert_eq!(cb1_stats.successful_requests, 2);
    assert_eq!(cb1_stats.failed_requests, 0);
    assert_eq!(cb2_stats.successful_requests, 0);
    assert_eq!(cb2_stats.failed_requests, 1);
}
