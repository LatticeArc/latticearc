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
fn test_auto_defaults_to_hybrid() {
    let config = TlsConfig::auto();
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
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Maximum), TlsMode::Pq);
}

#[test]
fn test_select_by_security_level_high() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::High), TlsMode::Hybrid);
}

#[test]
fn test_select_by_security_level_medium() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Medium), TlsMode::Hybrid);
}

#[test]
fn test_select_by_security_level_low() {
    assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Low), TlsMode::Classic);
}

// ============================================================================
// Balanced selection tests (security + performance)
// ============================================================================

#[test]
fn test_select_balanced_maximum_security_speed() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Maximum, PerformancePreference::Speed),
        TlsMode::Pq
    );
}

#[test]
fn test_select_balanced_maximum_security_balanced() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Maximum, PerformancePreference::Balanced),
        TlsMode::Pq
    );
}

#[test]
fn test_select_balanced_maximum_security_memory() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Maximum, PerformancePreference::Memory),
        TlsMode::Pq
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
fn test_select_balanced_medium_security_speed() {
    // Medium security + Speed preference = Classic
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Medium, PerformancePreference::Speed),
        TlsMode::Classic
    );
}

#[test]
fn test_select_balanced_medium_security_balanced() {
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Medium, PerformancePreference::Balanced),
        TlsMode::Hybrid
    );
}

#[test]
fn test_select_balanced_low_security_any_preference() {
    // Low security always returns Classic regardless of performance
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Low, PerformancePreference::Speed),
        TlsMode::Classic
    );
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Low, PerformancePreference::Balanced),
        TlsMode::Classic
    );
    assert_eq!(
        TlsPolicyEngine::select_balanced(SecurityLevel::Low, PerformancePreference::Memory),
        TlsMode::Classic
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
fn test_context_maximum_security_override() {
    // Even with a use case that recommends Hybrid, Maximum security should use PQ
    let ctx = TlsContext::default()
        .security_level(SecurityLevel::Maximum)
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
// TlsConfig convenience method tests
// ============================================================================

#[test]
fn test_tls_config_for_use_case_webserver() {
    let config = TlsConfig::for_use_case(TlsUseCase::WebServer);
    assert_eq!(config.mode, TlsMode::Hybrid);
}

#[test]
fn test_tls_config_for_use_case_iot() {
    let config = TlsConfig::for_use_case(TlsUseCase::IoT);
    assert_eq!(config.mode, TlsMode::Classic);
}

#[test]
fn test_tls_config_for_use_case_government() {
    let config = TlsConfig::for_use_case(TlsUseCase::Government);
    assert_eq!(config.mode, TlsMode::Pq);
}

#[test]
fn test_tls_config_with_security_level_maximum() {
    let config = TlsConfig::with_security_level(SecurityLevel::Maximum);
    assert_eq!(config.mode, TlsMode::Pq);
}

#[test]
fn test_tls_config_with_security_level_low() {
    let config = TlsConfig::with_security_level(SecurityLevel::Low);
    assert_eq!(config.mode, TlsMode::Classic);
}

#[test]
fn test_tls_config_from_context() {
    let ctx = TlsContext::default()
        .security_level(SecurityLevel::High)
        .performance_preference(PerformancePreference::Balanced)
        .use_case(TlsUseCase::FinancialServices);

    let config = TlsConfig::from_context(&ctx);
    assert_eq!(config.mode, TlsMode::Hybrid);
}

#[test]
fn test_tls_config_from_context_speed_preference() {
    let ctx = TlsContext::default().performance_preference(PerformancePreference::Speed);

    let config = TlsConfig::from_context(&ctx);
    // Speed preference should disable fallback
    assert!(!config.enable_fallback);
}

#[test]
fn test_tls_config_from_context_memory_preference() {
    let ctx = TlsContext::default().performance_preference(PerformancePreference::Memory);

    let config = TlsConfig::from_context(&ctx);
    // Memory preference should set smaller fragment size
    assert_eq!(config.max_fragment_size, Some(4096));
}

#[test]
fn test_tls_config_from_context_maximum_security() {
    let ctx = TlsContext::default().security_level(SecurityLevel::Maximum);

    let config = TlsConfig::from_context(&ctx);
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
    let ctx = TlsContext::default().security_level(SecurityLevel::Maximum);

    let config = TlsPolicyEngine::create_config(&ctx);
    assert_eq!(config.mode, TlsMode::Pq);
}
