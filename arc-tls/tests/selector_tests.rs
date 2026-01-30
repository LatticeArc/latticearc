//! Comprehensive tests for TLS auto-selector
//!
//! Tests cover:
//! - Mode recommendations for all use cases
//! - Security level mappings
//! - Balanced selection with performance preferences
//! - Context-aware selection with constraints
//! - TlsConfig convenience methods

use arc_core::{PerformancePreference, SecurityLevel};
use arc_tls::{TlsConfig, TlsConstraints, TlsContext, TlsMode, TlsPolicyEngine, TlsUseCase};

// ============================================================================
// Auto defaults tests
// ============================================================================

#[test]
fn test_new_defaults_to_hybrid() {
    let config = TlsConfig::new();
    // When PQ is available (default build), should be Hybrid
    if arc_tls::pq_enabled() {
        assert_eq!(config.mode, TlsMode::Hybrid);
    }
}

#[test]
fn test_default_tls_mode_is_hybrid() {
    assert_eq!(TlsMode::default(), TlsMode::Hybrid);
}

#[test]
fn test_default_tls_config_is_hybrid() {
    let config = TlsConfig::default();
    assert_eq!(config.mode, TlsMode::Hybrid);
}

// ============================================================================
// Use case recommendation tests
// ============================================================================

#[test]
fn test_recommend_mode_webserver() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::WebServer), TlsMode::Hybrid);
}

#[test]
fn test_recommend_mode_internal_service() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::InternalService), TlsMode::Hybrid);
}

#[test]
fn test_recommend_mode_api_gateway() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::ApiGateway), TlsMode::Hybrid);
}

#[test]
fn test_recommend_mode_iot() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::IoT), TlsMode::Classic);
}

#[test]
fn test_recommend_mode_legacy_integration() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::LegacyIntegration), TlsMode::Classic);
}

#[test]
fn test_recommend_mode_financial_services() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::FinancialServices), TlsMode::Hybrid);
}

#[test]
fn test_recommend_mode_healthcare() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::Healthcare), TlsMode::Hybrid);
}

#[test]
fn test_recommend_mode_government() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::Government), TlsMode::Pq);
}

#[test]
fn test_recommend_mode_database_connection() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::DatabaseConnection), TlsMode::Hybrid);
}

#[test]
fn test_recommend_mode_real_time_streaming() {
    assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::RealTimeStreaming), TlsMode::Classic);
}

// ============================================================================
// Security level selection tests
// ============================================================================

#[test]
fn test_select_by_security_level_maximum() {
    // Maximum uses Hybrid mode (only Quantum uses PQ-only)
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Maximum), TlsMode::Hybrid);
}

#[test]
fn test_select_by_security_level_high() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::High), TlsMode::Hybrid);
}

#[test]
fn test_select_by_security_level_standard() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Standard), TlsMode::Hybrid);
}

#[test]
fn test_select_by_security_level_quantum() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Quantum), TlsMode::Pq);
}

// ============================================================================
// Balanced selection tests (security + performance)
// ============================================================================

#[test]
fn test_select_balanced_maximum_security_speed() {
    // Maximum uses Hybrid mode (only Quantum uses PQ-only)
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Maximum, PerformancePreference::Speed),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_maximum_security_balanced() {
    // Maximum uses Hybrid mode (only Quantum uses PQ-only)
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Maximum, PerformancePreference::Balanced),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_maximum_security_memory() {
    // Maximum uses Hybrid mode (only Quantum uses PQ-only)
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Maximum, PerformancePreference::Memory),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_high_security_speed() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::High, PerformancePreference::Speed),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_high_security_balanced() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::High, PerformancePreference::Balanced),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_high_security_memory() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::High, PerformancePreference::Memory),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_standard_security_speed() {
    // Standard security + Speed preference = Hybrid (all non-Quantum levels use Hybrid)
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Standard, PerformancePreference::Speed),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_standard_security_balanced() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Standard, PerformancePreference::Balanced),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_quantum_security_any_preference() {
    // Quantum security always returns PQ-only regardless of performance
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Quantum, PerformancePreference::Speed),
        TlsMode::Pq
    );
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Quantum, PerformancePreference::Balanced),
        TlsMode::Pq
    );
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Quantum, PerformancePreference::Memory),
        TlsMode::Pq
    );
}

// ============================================================================
// Context-aware selection tests
// ============================================================================

#[test]
fn test_context_default() {
    let ctx = TlsContext::default();
    assert_eq!(ctx.security_level, SecurityLevel::High);
    assert_eq!(ctx.performance_preference, PerformancePreference::Balanced);
    assert!(ctx.use_case.is_none());
}

#[test]
fn test_context_with_use_case() {
    let ctx = TlsContext::with_use_case(TlsUseCase::Government);
    assert_eq!(ctx.use_case, Some(TlsUseCase::Government));
}

#[test]
fn test_context_with_security_level() {
    let ctx = TlsContext::with_security_level(SecurityLevel::Maximum);
    assert_eq!(ctx.security_level, SecurityLevel::Maximum);
}

#[test]
fn test_context_builder_pattern() {
    let ctx = TlsContext::default()
        .security_level(SecurityLevel::Maximum)
        .performance_preference(PerformancePreference::Speed)
        .use_case(TlsUseCase::Government)
        .pq_available(true);

    assert_eq!(ctx.security_level, SecurityLevel::Maximum);
    assert_eq!(ctx.performance_preference, PerformancePreference::Speed);
    assert_eq!(ctx.use_case, Some(TlsUseCase::Government));
    assert!(ctx.pq_available);
}

#[test]
fn test_context_pq_not_available_forces_classic() {
    let ctx = TlsContext::default().pq_available(false);
    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Classic);
}

#[test]
fn test_context_with_use_case_selection() {
    let ctx = TlsContext::with_use_case(TlsUseCase::Government);
    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Pq);
}

#[test]
fn test_context_maximum_security_with_webserver() {
    // Maximum security still uses Hybrid mode (only Quantum uses PQ-only)
    let ctx = TlsContext::default()
        .security_level(SecurityLevel::Maximum)
        .use_case(TlsUseCase::WebServer);

    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Hybrid);
}

#[test]
fn test_context_quantum_security_override() {
    // Quantum security should use PQ-only mode regardless of use case
    let ctx = TlsContext::default()
        .security_level(SecurityLevel::Quantum)
        .use_case(TlsUseCase::WebServer); // WebServer normally recommends Hybrid

    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Pq);
}

// ============================================================================
// Constraints tests
// ============================================================================

#[test]
fn test_constraints_default() {
    let constraints = TlsConstraints::default();
    assert!(!constraints.requires_classic());
    assert!(constraints.allows_pq());
}

#[test]
fn test_constraints_maximum_compatibility_requires_classic() {
    let constraints = TlsConstraints::maximum_compatibility();
    assert!(constraints.requires_classic());
    assert!(!constraints.allows_pq());
}

#[test]
fn test_constraints_high_security_allows_pq() {
    let constraints = TlsConstraints::high_security();
    assert!(!constraints.requires_classic());
    assert!(constraints.allows_pq());
}

#[test]
fn test_constraints_client_no_pq_support() {
    let constraints = TlsConstraints { client_supports_pq: Some(false), ..Default::default() };
    assert!(constraints.requires_classic());
    assert!(!constraints.allows_pq());
}

#[test]
fn test_constraints_require_compatibility() {
    let constraints = TlsConstraints { require_compatibility: true, ..Default::default() };
    assert!(constraints.requires_classic());
}

#[test]
fn test_constraints_strict_latency() {
    let constraints = TlsConstraints { max_handshake_latency_ms: Some(10), ..Default::default() };
    assert!(constraints.requires_classic());
}

#[test]
fn test_constraints_strict_size() {
    let constraints = TlsConstraints { max_client_hello_size: Some(512), ..Default::default() };
    assert!(constraints.requires_classic());
}

#[test]
fn test_context_with_constraints_forces_classic() {
    let ctx = TlsContext::default()
        .security_level(SecurityLevel::Maximum)
        .constraints(TlsConstraints::maximum_compatibility());

    let mode = TlsPolicyEngine::select_with_context(&ctx);
    assert_eq!(mode, TlsMode::Classic);
}

// ============================================================================
// TlsConfig builder method tests
// ============================================================================

#[test]
fn test_tls_config_with_use_case_webserver() {
    let config = TlsConfig::new().use_case(TlsUseCase::WebServer);
    assert_eq!(config.mode, TlsMode::Hybrid);
}

#[test]
fn test_tls_config_with_use_case_iot() {
    let config = TlsConfig::new().use_case(TlsUseCase::IoT);
    assert_eq!(config.mode, TlsMode::Classic);
}

#[test]
fn test_tls_config_with_use_case_government() {
    let config = TlsConfig::new().use_case(TlsUseCase::Government);
    assert_eq!(config.mode, TlsMode::Pq);
}

#[test]
fn test_tls_config_with_security_level_maximum() {
    // Maximum uses Hybrid mode (only Quantum uses PQ-only)
    let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
    assert_eq!(config.mode, TlsMode::Hybrid);
}

#[test]
fn test_tls_config_with_security_level_standard() {
    let config = TlsConfig::new().security_level(SecurityLevel::Standard);
    assert_eq!(config.mode, TlsMode::Hybrid);
}

#[test]
fn test_tls_config_with_security_level_quantum() {
    let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
    assert_eq!(config.mode, TlsMode::Pq);
}

#[test]
fn test_tls_config_builder_chain() {
    let config =
        TlsConfig::new().use_case(TlsUseCase::FinancialServices).with_tracing().with_fallback(true);

    assert_eq!(config.mode, TlsMode::Hybrid);
    assert!(config.enable_tracing);
    assert!(config.enable_fallback);
}

#[test]
fn test_tls_policy_engine_create_config_speed() {
    let ctx = TlsContext::default().performance_preference(PerformancePreference::Speed);

    let config = TlsPolicyEngine::create_config(&ctx);
    // Speed preference should disable fallback
    assert!(!config.enable_fallback);
}

#[test]
fn test_tls_policy_engine_create_config_memory() {
    let ctx = TlsContext::default().performance_preference(PerformancePreference::Memory);

    let config = TlsPolicyEngine::create_config(&ctx);
    // Memory preference should set smaller fragment size
    assert_eq!(config.max_fragment_size, Some(4096));
}

#[test]
fn test_tls_policy_engine_create_config_maximum_security() {
    let ctx = TlsContext::default().security_level(SecurityLevel::Maximum);

    let config = TlsPolicyEngine::create_config(&ctx);
    // Maximum security should disable early data
    assert!(!config.enable_early_data);
    assert!(config.require_secure_renegotiation);
}

// ============================================================================
// Coverage tests
// ============================================================================

#[test]
fn test_all_use_cases_have_recommendations() {
    for use_case in TlsUseCase::all() {
        let mode = TlsPolicyEngine::recommend_mode(*use_case);
        // Every use case should return a valid mode
        assert!(matches!(mode, TlsMode::Classic | TlsMode::Hybrid | TlsMode::Pq));
    }
}

#[test]
fn test_use_case_count() {
    // Ensure we have 10 use cases as documented
    assert_eq!(TlsUseCase::all().len(), 10);
}

#[test]
fn test_all_use_cases_have_descriptions() {
    for use_case in TlsUseCase::all() {
        let desc = use_case.description();
        assert!(!desc.is_empty());
    }
}

#[test]
fn test_use_case_equality() {
    assert_eq!(TlsUseCase::WebServer, TlsUseCase::WebServer);
    assert_ne!(TlsUseCase::WebServer, TlsUseCase::IoT);
}

#[test]
fn test_tls_mode_equality() {
    assert_eq!(TlsMode::Hybrid, TlsMode::Hybrid);
    assert_ne!(TlsMode::Classic, TlsMode::Pq);
}

// ============================================================================
// Create config tests
// ============================================================================

#[test]
fn test_create_config_classic() {
    let ctx = TlsContext::default().pq_available(false);

    let config = TlsPolicyEngine::create_config(&ctx);
    assert_eq!(config.mode, TlsMode::Classic);
}

#[test]
fn test_create_config_hybrid() {
    let ctx = TlsContext::default().security_level(SecurityLevel::High);

    let config = TlsPolicyEngine::create_config(&ctx);
    assert_eq!(config.mode, TlsMode::Hybrid);
}

#[test]
fn test_create_config_pq() {
    // Only Quantum security level creates PQ-only config
    let ctx = TlsContext::default().security_level(SecurityLevel::Quantum);

    let config = TlsPolicyEngine::create_config(&ctx);
    assert_eq!(config.mode, TlsMode::Pq);
}

#[test]
fn test_create_config_maximum() {
    // Maximum security level uses Hybrid mode
    let ctx = TlsContext::default().security_level(SecurityLevel::Maximum);

    let config = TlsPolicyEngine::create_config(&ctx);
    assert_eq!(config.mode, TlsMode::Hybrid);
}
