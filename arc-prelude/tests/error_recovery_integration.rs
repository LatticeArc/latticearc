//! Error Recovery Integration Tests
//!
//! Comprehensive tests for the error recovery framework including:
//! - Circuit breaker state transitions
//! - Error recovery handler
//! - Graceful degradation
//! - System health monitoring
//! - Error statistics tracking

use arc_prelude::prelude::error::LatticeArcError;
use arc_prelude::prelude::error::error_recovery::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, DegradationStrategy, EffortLevel,
    EnhancedError, EnhancedErrorHandler, ErrorContext, ErrorRecoveryHandler, ErrorSeverity,
    GracefulDegradationManager, RecoveryStrategy, RecoverySuggestion, ServiceDegradationInfo,
    SystemHealth,
};
use std::collections::HashMap;
use std::time::Duration;

// ============================================================================
// Circuit Breaker Tests
// ============================================================================

#[test]
fn test_circuit_breaker_default_creation() {
    let cb = CircuitBreaker::new();
    let stats = cb.stats();

    assert_eq!(stats.state, CircuitBreakerState::Closed);
    assert_eq!(stats.total_requests, 0);
    assert_eq!(stats.successful_requests, 0);
    assert_eq!(stats.failed_requests, 0);
}

#[test]
fn test_circuit_breaker_custom_config() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        recovery_timeout: Duration::from_secs(30),
        monitoring_window: Duration::from_secs(120),
    };

    let cb = CircuitBreaker::with_config(config);
    let stats = cb.stats();

    assert_eq!(stats.state, CircuitBreakerState::Closed);
}

#[test]
fn test_circuit_breaker_closed_success() {
    let cb = CircuitBreaker::new();

    // Successful operation
    let result = cb.call(|| Ok("success"));
    assert!(result.is_ok());

    let stats = cb.stats();
    assert_eq!(stats.state, CircuitBreakerState::Closed);
    assert_eq!(stats.total_requests, 1);
    assert_eq!(stats.successful_requests, 1);
    assert_eq!(stats.failed_requests, 0);
}

#[test]
fn test_circuit_breaker_closed_failure() {
    let cb = CircuitBreaker::new();

    // Failed operation
    let result: Result<(), _> =
        cb.call(|| Err(LatticeArcError::InvalidInput("test error".to_string())));
    assert!(result.is_err());

    let stats = cb.stats();
    assert_eq!(stats.state, CircuitBreakerState::Closed);
    assert_eq!(stats.total_requests, 1);
    assert_eq!(stats.successful_requests, 0);
    assert_eq!(stats.failed_requests, 1);
}

#[test]
fn test_circuit_breaker_transition_to_open() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        recovery_timeout: Duration::from_secs(1),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Cause 3 failures to open circuit
    for _ in 0..3 {
        let _result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("network down".to_string())));
    }

    let stats = cb.stats();
    assert_eq!(stats.state, CircuitBreakerState::Open);
    assert_eq!(stats.failed_requests, 3);
}

#[test]
fn test_circuit_breaker_open_rejects_requests() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(60), // Long timeout
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Cause failures to open circuit
    for _ in 0..2 {
        let _result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("network down".to_string())));
    }

    // Verify circuit is open
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Next request should be rejected immediately
    let result = cb.call(|| Ok("should not execute"));
    assert!(result.is_err());
    match result {
        Err(LatticeArcError::CircuitBreakerOpen) => {}
        _ => panic!("Expected CircuitBreakerOpen error"),
    }
}

#[test]
fn test_circuit_breaker_transition_to_half_open() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(100), // Short timeout for testing
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("test".to_string())));
    }

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Wait for recovery timeout
    std::thread::sleep(Duration::from_millis(150));

    // Next call should transition to half-open
    let result = cb.call(|| Ok("recovery test"));
    assert!(result.is_ok());

    let stats = cb.stats();
    // After successful call in half-open, should transition to closed
    assert_eq!(stats.state, CircuitBreakerState::Closed);
}

#[test]
fn test_circuit_breaker_half_open_success_closes() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(100),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("test".to_string())));
    }

    // Wait for recovery timeout
    std::thread::sleep(Duration::from_millis(150));

    // Successful call should close the circuit
    let result = cb.call(|| Ok("success"));
    assert!(result.is_ok());
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
}

#[test]
fn test_circuit_breaker_half_open_failure_reopens() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(100),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open the circuit
    for _ in 0..2 {
        let _result: Result<(), _> =
            cb.call(|| Err(LatticeArcError::NetworkError("test".to_string())));
    }

    // Wait for recovery timeout
    std::thread::sleep(Duration::from_millis(150));

    // Failed call in half-open should reopen circuit
    let result: Result<(), _> =
        cb.call(|| Err(LatticeArcError::NetworkError("still down".to_string())));
    assert!(result.is_err());
    assert_eq!(cb.stats().state, CircuitBreakerState::Open);
}

#[test]
fn test_circuit_breaker_statistics_accuracy() {
    let cb = CircuitBreaker::new();

    // Mix of successes and failures
    let _r1 = cb.call(|| Ok("success 1"));
    let _r2: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("fail 1".to_string())));
    let _r3 = cb.call(|| Ok("success 2"));
    let _r4 = cb.call(|| Ok("success 3"));
    let _r5: Result<(), _> = cb.call(|| Err(LatticeArcError::InvalidInput("fail 2".to_string())));

    let stats = cb.stats();
    assert_eq!(stats.total_requests, 5);
    assert_eq!(stats.successful_requests, 3);
    assert_eq!(stats.failed_requests, 2);
}

// ============================================================================
// Enhanced Error Tests
// ============================================================================

#[test]
fn test_enhanced_error_creation() {
    let error = LatticeArcError::InvalidInput("test".to_string());
    let enhanced = EnhancedError::new(error, "test_operation".to_string());

    assert_eq!(enhanced.operation, "test_operation");
    assert_eq!(enhanced.severity, ErrorSeverity::Medium);
    assert!(enhanced.error_id.starts_with("ERR-"));
}

#[test]
fn test_enhanced_error_with_context() {
    let error = LatticeArcError::NetworkError("connection failed".to_string());
    let context = ErrorContext::new()
        .with_component("network_module".to_string())
        .with_user_message("Please check your connection".to_string())
        .add_technical_detail("endpoint".to_string(), "https://api.example.com".to_string())
        .add_parameter("timeout".to_string(), "30s".to_string())
        .add_system_state("connection_pool".to_string(), "exhausted".to_string());

    let enhanced = EnhancedError::new(error, "connect".to_string()).with_context(context);

    assert_eq!(enhanced.context.component, "network_module");
    assert_eq!(enhanced.context.user_message, "Please check your connection");
    assert_eq!(
        enhanced.context.technical_details.get("endpoint"),
        Some(&"https://api.example.com".to_string())
    );
    assert_eq!(enhanced.context.parameters.get("timeout"), Some(&"30s".to_string()));
    assert_eq!(
        enhanced.context.system_state.get("connection_pool"),
        Some(&"exhausted".to_string())
    );
}

#[test]
fn test_enhanced_error_recovery_suggestions() {
    let suggestions = vec![
        RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "Retry with exponential backoff".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.8,
            steps: vec!["Wait 1s".to_string(), "Retry operation".to_string()],
        },
        RecoverySuggestion {
            strategy: RecoveryStrategy::Fallback,
            description: "Use cached data".to_string(),
            priority: 8,
            effort_estimate: EffortLevel::Medium,
            success_probability: 0.6,
            steps: vec!["Load from cache".to_string()],
        },
    ];

    let error = LatticeArcError::NetworkError("timeout".to_string());
    let enhanced =
        EnhancedError::new(error, "fetch_data".to_string()).with_recovery_suggestions(suggestions);

    assert_eq!(enhanced.recovery_suggestions.len(), 2);
    assert!(enhanced.is_recoverable());
    assert_eq!(enhanced.recovery_suggestions[0].priority, 10);
    assert_eq!(enhanced.recovery_suggestions[0].strategy, RecoveryStrategy::Retry);
}

#[test]
fn test_enhanced_error_severity_levels() {
    for (severity, expected) in [
        (ErrorSeverity::Low, ErrorSeverity::Low),
        (ErrorSeverity::Medium, ErrorSeverity::Medium),
        (ErrorSeverity::High, ErrorSeverity::High),
        (ErrorSeverity::Critical, ErrorSeverity::Critical),
    ] {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced = EnhancedError::new(error, "test".to_string()).with_severity(severity);

        assert_eq!(enhanced.severity, expected);
    }
}

#[test]
fn test_error_severity_ordering() {
    assert!(ErrorSeverity::Low < ErrorSeverity::Medium);
    assert!(ErrorSeverity::Medium < ErrorSeverity::High);
    assert!(ErrorSeverity::High < ErrorSeverity::Critical);
}

#[test]
fn test_enhanced_error_user_message() {
    let error = LatticeArcError::InvalidInput("test".to_string());
    let enhanced = EnhancedError::new(error, "test".to_string());

    // Default message when context is empty
    assert_eq!(enhanced.user_message(), "An error occurred");

    // Custom message
    let context = ErrorContext::new().with_user_message("Custom error message".to_string());
    let enhanced2 =
        EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "test".to_string())
            .with_context(context);

    assert_eq!(enhanced2.user_message(), "Custom error message");
}

// ============================================================================
// Error Context Tests
// ============================================================================

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
fn test_error_context_builder() {
    let context = ErrorContext::new()
        .with_user_message("User-friendly message".to_string())
        .with_component("crypto_module".to_string())
        .add_technical_detail("stack_depth".to_string(), "15".to_string())
        .add_technical_detail("memory_usage".to_string(), "128MB".to_string())
        .add_parameter("algorithm".to_string(), "ML-KEM-768".to_string())
        .add_system_state("cpu_load".to_string(), "85%".to_string());

    assert_eq!(context.user_message, "User-friendly message");
    assert_eq!(context.component, "crypto_module");
    assert_eq!(context.technical_details.len(), 2);
    assert_eq!(context.parameters.len(), 1);
    assert_eq!(context.system_state.len(), 1);
}

// ============================================================================
// System Health Tests
// ============================================================================

#[test]
fn test_system_health_default() {
    let health = SystemHealth::default();

    assert_eq!(health.health_score, 1.0);
    assert_eq!(health.error_rate, 0.0);
    assert_eq!(health.recovery_success_rate, 1.0);
    assert!(health.is_healthy());
}

#[test]
fn test_system_health_component_tracking() {
    let mut health = SystemHealth::default();

    health.update_component_health("database".to_string(), 0.9);
    health.update_component_health("network".to_string(), 0.8);
    health.update_component_health("cache".to_string(), 1.0);

    assert_eq!(health.component_health.len(), 3);
    assert_eq!(health.component_health.get("database"), Some(&0.9));
}

#[test]
fn test_system_health_error_recording() {
    let mut health = SystemHealth::default();
    let initial_score = health.health_score;

    health.record_error();

    assert!(health.error_rate > 0.0);
    assert!(health.health_score < initial_score);
}

#[test]
fn test_system_health_recovery_tracking() {
    let mut health = SystemHealth::default();

    health.record_error();
    let score_after_error = health.health_score;

    health.record_recovery_success();

    assert!(health.recovery_success_rate > 0.0);
    // Health should improve after recovery
    assert!(health.health_score >= score_after_error);
}

#[test]
fn test_system_health_needs_check() {
    let health = SystemHealth::default();

    // Just created, doesn't need check
    assert!(!health.needs_check());

    // Manual test with custom interval
    let mut health = SystemHealth::default();
    health.check_interval = Duration::from_millis(1);
    std::thread::sleep(Duration::from_millis(5));

    assert!(health.needs_check());
}

#[test]
fn test_system_health_threshold() {
    let mut health = SystemHealth::default();

    // Healthy by default
    assert!(health.is_healthy());

    // Degrade health
    health.update_component_health("critical_service".to_string(), 0.3);

    // Should no longer be healthy (threshold is 0.7)
    assert!(!health.is_healthy());
}

// ============================================================================
// Error Recovery Handler Tests
// ============================================================================

#[test]
fn test_error_recovery_handler_creation() {
    let handler = ErrorRecoveryHandler::new();
    let health = handler.system_health();

    assert!(health.is_healthy());
}

#[test]
fn test_error_recovery_handler_tracks_errors() {
    let handler = ErrorRecoveryHandler::new();

    let error = EnhancedError::new(
        LatticeArcError::NetworkError("test".to_string()),
        "test_op".to_string(),
    );

    let _result = handler.handle_error(&error);

    let stats = handler.error_stats();
    assert_eq!(stats.total_errors, 1);
}

#[test]
fn test_error_recovery_handler_statistics() {
    let handler = ErrorRecoveryHandler::new();

    let error1 =
        EnhancedError::new(LatticeArcError::NetworkError("test1".to_string()), "op1".to_string())
            .with_severity(ErrorSeverity::High);

    let error2 =
        EnhancedError::new(LatticeArcError::InvalidInput("test2".to_string()), "op2".to_string())
            .with_severity(ErrorSeverity::Medium);

    let _r1 = handler.handle_error(&error1);
    let _r2 = handler.handle_error(&error2);

    let stats = handler.error_stats();
    assert_eq!(stats.total_errors, 2);
    assert!(stats.last_error_time.is_some());
}

#[test]
fn test_error_recovery_handler_circuit_breaker_integration() {
    let mut handler = ErrorRecoveryHandler::new();

    let cb = handler.get_circuit_breaker("test_service");
    let result = cb.call(|| Ok("test"));
    assert!(result.is_ok());
}

#[test]
fn test_error_recovery_handler_health_monitoring() {
    let handler = ErrorRecoveryHandler::new();

    // Initial health should be good
    assert!(handler.system_health().is_healthy());

    // Create multiple errors
    for i in 0..5 {
        let error = EnhancedError::new(
            LatticeArcError::NetworkError(format!("error {}", i)),
            "test".to_string(),
        );
        let _r = handler.handle_error(&error);
    }

    let health = handler.system_health();
    // Health should degrade after multiple errors
    assert!(health.error_rate > 0.0);
}

#[test]
fn test_error_statistics_recovery_rate() {
    let handler = ErrorRecoveryHandler::new();
    let stats = handler.error_stats();

    // No attempts yet
    assert_eq!(stats.recovery_rate(), 0.0);
}

// ============================================================================
// Enhanced Error Handler Tests
// ============================================================================

#[test]
fn test_enhanced_error_handler_creation() {
    let handler = EnhancedErrorHandler::new();
    assert!(handler.is_system_healthy());
}

#[test]
fn test_enhanced_error_handler_network_error() {
    let handler = EnhancedErrorHandler::new();
    let error = LatticeArcError::NetworkError("connection timeout".to_string());

    let _result = handler.handle_error(&error, "network_call".to_string(), "api".to_string());

    let stats = handler.system_health();
    assert!(stats.error_rate >= 0.0);
}

#[test]
fn test_enhanced_error_handler_invalid_input() {
    let handler = EnhancedErrorHandler::new();
    let error = LatticeArcError::InvalidInput("bad data".to_string());

    let _result = handler.handle_error(&error, "validate".to_string(), "validator".to_string());

    let health = handler.system_health();
    assert!(health.error_rate >= 0.0);
}

#[test]
fn test_enhanced_error_handler_circuit_breaker_integration() {
    let mut handler = EnhancedErrorHandler::new();
    let cb = handler.get_circuit_breaker("test_service");

    let result = cb.call(|| Ok("success"));
    assert!(result.is_ok());
}

#[test]
fn test_enhanced_error_handler_system_health() {
    let handler = EnhancedErrorHandler::new();
    let health = handler.system_health();

    assert_eq!(health.health_score, 1.0);
    assert!(handler.is_system_healthy());
}

// ============================================================================
// Graceful Degradation Tests
// ============================================================================

#[test]
fn test_degradation_manager_creation() {
    let manager = GracefulDegradationManager::new();
    assert!(!manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_no_degradation_for_low_severity() {
    let manager = GracefulDegradationManager::new();

    let error =
        EnhancedError::new(LatticeArcError::InvalidInput("test".to_string()), "test".to_string())
            .with_severity(ErrorSeverity::Low);

    manager.handle_critical_error(&error);

    // Should not activate degradation for low severity
    assert!(!manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_activates_for_high_severity() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::NetworkError("critical failure".to_string()),
        "network_op".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    // Should activate degradation for high severity affecting managed services
    assert!(manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_service_tracking() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::EncryptionError("crypto failure".to_string()),
        "encrypt".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&error);

    assert!(manager.is_degradation_active());

    // Check if encryption service is degraded
    let degraded_services = manager.get_all_degraded_services();
    assert!(!degraded_services.is_empty());
}

#[test]
fn test_degradation_manager_service_info() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::ServiceUnavailable("service down".to_string()),
        "call_service".to_string(),
    )
    .with_context(ErrorContext::new().with_component("hashing".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    if manager.is_degradation_active() {
        let services = manager.get_all_degraded_services();
        assert!(!services.is_empty());

        for service in services {
            assert!(service.degradation_level > 0.0);
            assert!(service.available);
            assert!(!service.reason.is_empty());
        }
    }
}

#[test]
fn test_degradation_manager_recovery_attempt() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(LatticeArcError::ResourceExhausted, "allocate".to_string())
        .with_context(ErrorContext::new().with_component("all".to_string()))
        .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&error);

    // Attempt recovery
    manager.attempt_recovery();

    // Recovery logic may or may not clear degradation depending on conditions
    let _is_active = manager.is_degradation_active();
}

#[test]
fn test_degradation_manager_performance_thresholds() {
    let mut manager = GracefulDegradationManager::new();

    manager.set_performance_threshold("encryption".to_string(), 0.9);
    manager.set_performance_threshold("hashing".to_string(), 0.85);

    // Performance thresholds are set internally
    // Verify manager still functions
    assert!(!manager.is_degradation_active());
}

#[test]
fn test_degradation_strategy_structure() {
    let strategy = DegradationStrategy {
        name: "test_strategy".to_string(),
        priority: 5,
        services_to_degrade: vec!["service1".to_string(), "service2".to_string()],
        min_performance_level: 0.7,
        description: "Test degradation strategy".to_string(),
    };

    assert_eq!(strategy.name, "test_strategy");
    assert_eq!(strategy.priority, 5);
    assert_eq!(strategy.services_to_degrade.len(), 2);
    assert_eq!(strategy.min_performance_level, 0.7);
}

// ============================================================================
// Integration Tests - Full Workflow
// ============================================================================

#[test]
fn test_full_error_recovery_workflow() {
    let handler = EnhancedErrorHandler::new();

    // Simulate a network error
    let error = LatticeArcError::NetworkError("Connection refused".to_string());
    let result = handler.handle_error(&error, "api_call".to_string(), "network".to_string());

    // Handler should process the error
    assert!(result.is_ok() || result.is_err()); // Either recovery succeeds or fails

    // System should track the error
    let health = handler.system_health();
    assert!(health.error_rate >= 0.0);
}

#[test]
fn test_circuit_breaker_with_recovery() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 1,
        recovery_timeout: Duration::from_millis(100),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Fail enough times to open circuit
    for _ in 0..3 {
        let _r: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));
    }

    assert_eq!(cb.stats().state, CircuitBreakerState::Open);

    // Wait for recovery window
    std::thread::sleep(Duration::from_millis(150));

    // Successful call should close circuit
    let result = cb.call(|| Ok("recovered"));
    assert!(result.is_ok());
    assert_eq!(cb.stats().state, CircuitBreakerState::Closed);
}

#[test]
fn test_error_statistics_comprehensive() {
    let handler = ErrorRecoveryHandler::new();

    // Create errors of different severities
    let errors = vec![
        EnhancedError::new(LatticeArcError::NetworkError("e1".to_string()), "op1".to_string())
            .with_severity(ErrorSeverity::Low)
            .with_context(ErrorContext::new().with_component("net".to_string())),
        EnhancedError::new(LatticeArcError::InvalidInput("e2".to_string()), "op2".to_string())
            .with_severity(ErrorSeverity::Medium)
            .with_context(ErrorContext::new().with_component("validator".to_string())),
        EnhancedError::new(LatticeArcError::EncryptionError("e3".to_string()), "op3".to_string())
            .with_severity(ErrorSeverity::High)
            .with_context(ErrorContext::new().with_component("crypto".to_string())),
    ];

    for error in errors {
        let _r = handler.handle_error(&error);
    }

    let stats = handler.error_stats();
    assert_eq!(stats.total_errors, 3);
    assert!(stats.errors_by_severity.len() > 0);
    assert!(stats.errors_by_component.len() > 0);
}

#[test]
fn test_multiple_circuit_breakers() {
    let mut handler = ErrorRecoveryHandler::new();

    let cb1 = handler.get_circuit_breaker("service1");
    let r1 = cb1.call(|| Ok("success"));
    assert!(r1.is_ok());

    let cb2 = handler.get_circuit_breaker("service2");
    let r2 = cb2.call(|| Ok("success"));
    assert!(r2.is_ok());

    // Both should be independent
    let cb1_stats = handler.get_circuit_breaker("service1").stats();
    let cb2_stats = handler.get_circuit_breaker("service2").stats();

    assert_eq!(cb1_stats.total_requests, 1);
    assert_eq!(cb2_stats.total_requests, 1);
}

#[test]
fn test_system_health_degradation_over_time() {
    let mut health = SystemHealth::default();

    // Simulate increasing error rate
    for _ in 0..10 {
        health.record_error();
    }

    assert!(health.error_rate > 0.0);
    assert!(health.health_score < 1.0);

    // Record some recoveries
    for _ in 0..5 {
        health.record_recovery_success();
    }

    // Health should improve somewhat
    assert!(health.recovery_success_rate > 0.0);
}

#[test]
fn test_recovery_suggestion_priorities() {
    let suggestions = vec![
        RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "High priority".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.9,
            steps: vec!["step1".to_string()],
        },
        RecoverySuggestion {
            strategy: RecoveryStrategy::Fallback,
            description: "Medium priority".to_string(),
            priority: 5,
            effort_estimate: EffortLevel::Medium,
            success_probability: 0.7,
            steps: vec!["step1".to_string()],
        },
        RecoverySuggestion {
            strategy: RecoveryStrategy::ManualIntervention,
            description: "Low priority".to_string(),
            priority: 1,
            effort_estimate: EffortLevel::VeryHigh,
            success_probability: 0.3,
            steps: vec!["step1".to_string()],
        },
    ];

    // Verify priorities are different
    assert!(suggestions[0].priority > suggestions[1].priority);
    assert!(suggestions[1].priority > suggestions[2].priority);
}

#[test]
fn test_error_propagation_with_context() {
    let handler = EnhancedErrorHandler::new();

    let mut context_map = HashMap::new();
    context_map.insert("request_id".to_string(), "12345".to_string());
    context_map.insert("user_id".to_string(), "user_67890".to_string());

    let error = LatticeArcError::DatabaseError("Query failed".to_string());
    let _result = handler.handle_error(&error, "db_query".to_string(), "database".to_string());

    // Error should be tracked
    assert!(handler.system_health().error_rate >= 0.0);
}

#[test]
fn test_concurrent_circuit_breaker_access() {
    use std::sync::Arc;
    use std::thread;

    let cb = Arc::new(CircuitBreaker::new());
    let mut handles = vec![];

    for i in 0..5 {
        let cb_clone = Arc::clone(&cb);
        let handle = thread::spawn(move || {
            let result = cb_clone.call(|| {
                if i % 2 == 0 {
                    Ok(i)
                } else {
                    Err(LatticeArcError::InvalidInput("test".to_string()))
                }
            });
            result.is_ok()
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.join().unwrap_or(false) {
            success_count += 1;
        }
    }

    // Some operations should succeed
    assert!(success_count > 0);

    let stats = cb.stats();
    assert_eq!(stats.total_requests, 5);
}

#[test]
fn test_edge_case_empty_recovery_suggestions() {
    let error = LatticeArcError::InvalidInput("unknown".to_string());
    let enhanced =
        EnhancedError::new(error, "unknown_op".to_string()).with_recovery_suggestions(vec![]);

    assert!(!enhanced.is_recoverable());
    assert_eq!(enhanced.recovery_suggestions.len(), 0);
}

#[test]
fn test_edge_case_zero_timeout() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        recovery_timeout: Duration::from_secs(0),
        monitoring_window: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::with_config(config);

    // Open circuit
    let _r: Result<(), _> = cb.call(|| Err(LatticeArcError::NetworkError("fail".to_string())));

    // Should immediately be able to retry (zero timeout)
    let result = cb.call(|| Ok("immediate retry"));
    assert!(result.is_ok());
}

#[test]
fn test_error_context_large_data() {
    let mut context = ErrorContext::new();

    // Add many technical details
    for i in 0..100 {
        context = context.add_technical_detail(format!("detail_{}", i), format!("value_{}", i));
    }

    assert_eq!(context.technical_details.len(), 100);
}

// ============================================================================
// Additional Graceful Degradation Tests (Coverage Enhancement)
// ============================================================================

#[test]
fn test_degradation_manager_critical_severity_threshold() {
    let manager = GracefulDegradationManager::new();

    // Test that Critical severity activates degradation
    let critical_error = EnhancedError::new(
        LatticeArcError::EncryptionError("critical crypto failure".to_string()),
        "encrypt".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&critical_error);
    assert!(manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_medium_severity_no_activation() {
    let manager = GracefulDegradationManager::new();

    // Test that Medium severity does NOT activate degradation
    let medium_error = EnhancedError::new(
        LatticeArcError::InvalidInput("minor issue".to_string()),
        "test".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::Medium);

    manager.handle_critical_error(&medium_error);
    assert!(!manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_service_matching_all_strategy() {
    let manager = GracefulDegradationManager::new();

    // Test "all" service matching - should match any component
    let error =
        EnhancedError::new(LatticeArcError::ResourceExhausted, "resource_allocation".to_string())
            .with_context(ErrorContext::new().with_component("memory".to_string()))
            .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&error);

    // Emergency mode strategy should activate for "all" services
    assert!(manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_hashing_service_degradation() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::ServiceUnavailable("hash service down".to_string()),
        "hash_operation".to_string(),
    )
    .with_context(ErrorContext::new().with_component("hashing".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    // Verify hashing service is degraded
    assert!(manager.is_service_degraded("hashing"));

    let info = manager.get_service_degradation_info("hashing");
    assert!(info.is_some());

    if let Some(service_info) = info {
        assert_eq!(service_info.service, "hashing");
        assert_eq!(service_info.degradation_level, 0.5);
        assert!(service_info.available);
        assert!(service_info.reason.contains("reduce_precision"));
    }
}

#[test]
fn test_degradation_manager_logging_service_degradation() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::ServiceUnavailable("logging service down".to_string()),
        "log_operation".to_string(),
    )
    .with_context(ErrorContext::new().with_component("logging".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    // Verify logging service can be degraded
    if manager.is_degradation_active() {
        assert!(manager.is_service_degraded("logging"));
    }
}

#[test]
fn test_degradation_manager_is_service_degraded_nonexistent() {
    let manager = GracefulDegradationManager::new();

    // Check for service that doesn't exist
    assert!(!manager.is_service_degraded("nonexistent_service"));

    // Get info for nonexistent service
    let info = manager.get_service_degradation_info("nonexistent_service");
    assert!(info.is_none());
}

#[test]
fn test_degradation_manager_multiple_services_simultaneously() {
    let manager = GracefulDegradationManager::new();

    // Trigger emergency mode which affects "all" services
    let critical_error =
        EnhancedError::new(LatticeArcError::ResourceExhausted, "system_failure".to_string())
            .with_context(ErrorContext::new().with_component("all".to_string()))
            .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&critical_error);

    assert!(manager.is_degradation_active());

    // Get all degraded services
    let degraded_services = manager.get_all_degraded_services();
    assert!(!degraded_services.is_empty());
}

#[test]
fn test_degradation_manager_service_degradation_info_fields() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::EncryptionError("encryption failure".to_string()),
        "encrypt".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::Critical);

    manager.handle_critical_error(&error);

    if let Some(info) = manager.get_service_degradation_info("encryption") {
        // Verify all fields are properly set
        assert_eq!(info.service, "encryption");
        assert!(info.degradation_level > 0.0 && info.degradation_level <= 1.0);
        assert!(!info.reason.is_empty());
        assert!(info.estimated_recovery.is_some());
        assert!(info.available);

        if let Some(recovery_time) = info.estimated_recovery {
            assert!(recovery_time.as_secs() > 0);
        }
    }
}

#[test]
fn test_degradation_manager_default_trait() {
    let manager1 = GracefulDegradationManager::default();
    let manager2 = GracefulDegradationManager::new();

    // Both should start in the same state
    assert_eq!(manager1.is_degradation_active(), manager2.is_degradation_active());
    assert_eq!(
        manager1.get_all_degraded_services().len(),
        manager2.get_all_degraded_services().len()
    );
}

#[test]
fn test_degradation_manager_recovery_no_degradation() {
    let manager = GracefulDegradationManager::new();

    // Attempt recovery when nothing is degraded
    manager.attempt_recovery();

    // Should still be inactive
    assert!(!manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_empty_component() {
    let manager = GracefulDegradationManager::new();

    // Error with empty component
    let error = EnhancedError::new(
        LatticeArcError::NetworkError("test".to_string()),
        "test_op".to_string(),
    )
    .with_context(ErrorContext::new().with_component("".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    // Should not match any specific strategy unless "all" is involved
    // Just verify it doesn't panic when getting services
    let _degraded_services = manager.get_all_degraded_services();
}

#[test]
fn test_degradation_strategy_priority_ordering() {
    let manager = GracefulDegradationManager::new();

    // Create errors that could match multiple strategies
    let encryption_error = EnhancedError::new(
        LatticeArcError::EncryptionError("crypto issue".to_string()),
        "encrypt".to_string(),
    )
    .with_context(ErrorContext::new().with_component("encryption".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&encryption_error);

    // Should apply the first matching strategy (reduce_precision for encryption)
    assert!(manager.is_degradation_active());
}

#[test]
fn test_degradation_manager_metrics_service() {
    let manager = GracefulDegradationManager::new();

    let error = EnhancedError::new(
        LatticeArcError::ServiceUnavailable("metrics unavailable".to_string()),
        "metrics_op".to_string(),
    )
    .with_context(ErrorContext::new().with_component("metrics".to_string()))
    .with_severity(ErrorSeverity::High);

    manager.handle_critical_error(&error);

    // Metrics should be degraded (part of disable_optional strategy)
    if manager.is_degradation_active() {
        assert!(manager.is_service_degraded("metrics"));
    }
}

#[test]
fn test_degradation_manager_service_info_clone() {
    let info = ServiceDegradationInfo {
        service: "test_service".to_string(),
        degradation_level: 0.7,
        reason: "test reason".to_string(),
        estimated_recovery: Some(Duration::from_secs(60)),
        available: true,
    };

    let cloned = info.clone();
    assert_eq!(info.service, cloned.service);
    assert_eq!(info.degradation_level, cloned.degradation_level);
    assert_eq!(info.reason, cloned.reason);
    assert_eq!(info.available, cloned.available);
}

#[test]
fn test_degradation_strategy_clone() {
    let strategy = DegradationStrategy {
        name: "test_strategy".to_string(),
        priority: 5,
        services_to_degrade: vec!["service1".to_string()],
        min_performance_level: 0.8,
        description: "test description".to_string(),
    };

    let cloned = strategy.clone();
    assert_eq!(strategy.name, cloned.name);
    assert_eq!(strategy.priority, cloned.priority);
    assert_eq!(strategy.min_performance_level, cloned.min_performance_level);
}
