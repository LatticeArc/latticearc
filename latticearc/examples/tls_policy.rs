//! TLS Policy Engine Example
//!
//! Demonstrates ALL 10 TLS use cases with TlsPolicyEngine mode selection,
//! scheme selection, context-aware selection, and TlsConfig builder pattern.
//!
//! Run with: `cargo run --package latticearc --example tls_policy --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::panic)]

use latticearc::{
    PerformancePreference, SecurityLevel, TlsConfig, TlsConstraints, TlsContext, TlsMode,
    TlsPolicyEngine, TlsUseCase,
};

fn main() {
    println!("=== LatticeArc: TLS Policy Engine — Comprehensive Happy-Path Tests ===\n");

    // ====================================================================
    // Section 1: All 10 TlsUseCases — mode recommendation
    // ====================================================================
    println!("--- All 10 TlsUseCases: recommend_mode ---\n");

    let use_cases = TlsUseCase::all();
    assert_eq!(use_cases.len(), 10, "Expected 10 TLS use cases");

    for uc in use_cases {
        let mode = TlsPolicyEngine::recommend_mode(*uc);
        let desc = uc.description();
        println!("  {:25} -> {:?}  ({})", format!("{:?}", uc), mode, desc);
    }
    println!("\n  All 10 TLS use cases have mode recommendations!\n");

    // ====================================================================
    // Section 2: All 10 TlsUseCases — scheme + KEX selection
    // ====================================================================
    println!("--- All 10 TlsUseCases: scheme + KEX identifiers ---\n");

    for uc in use_cases {
        let mode = TlsPolicyEngine::recommend_mode(*uc);
        let level = SecurityLevel::High;
        let scheme = TlsPolicyEngine::get_scheme_identifier(mode, level.clone());
        let kex = TlsPolicyEngine::get_kex_algorithm(mode, level);
        println!("  {:25} mode={:?}  scheme={:35} kex={}", format!("{:?}", uc), mode, scheme, kex);
    }
    println!("\n  All 10 TLS use cases have scheme + KEX selections!\n");

    // ====================================================================
    // Section 3: All 4 SecurityLevels — TLS mode selection
    // ====================================================================
    println!("--- All 4 SecurityLevels: TLS mode via select_by_security_level ---\n");

    let levels: &[(&str, SecurityLevel)] = &[
        ("Standard", SecurityLevel::Standard),
        ("High", SecurityLevel::High),
        ("Maximum", SecurityLevel::Maximum),
        ("Quantum", SecurityLevel::Quantum),
    ];

    for (name, level) in levels {
        let mode = TlsPolicyEngine::select_by_security_level(level.clone());
        let scheme = TlsPolicyEngine::get_scheme_identifier(mode, level.clone());
        let kex = TlsPolicyEngine::get_kex_algorithm(mode, level.clone());
        println!("  {:10} -> {:?}  scheme={:35} kex={}", name, mode, scheme, kex);
    }
    println!("\n  All 4 security levels produce valid TLS modes!\n");

    // ====================================================================
    // Section 4: TlsContext-based selection (full context awareness)
    // ====================================================================
    println!("--- TlsContext: select_with_context for each use case ---\n");

    for uc in use_cases {
        let ctx = TlsContext::with_use_case(*uc);
        let mode = TlsPolicyEngine::select_with_context(&ctx);
        let config = TlsPolicyEngine::create_config(&ctx);
        println!(
            "  {:25} context_mode={:?}  config_mode={:?}  fallback={}",
            format!("{:?}", uc),
            mode,
            config.mode,
            config.enable_fallback,
        );
    }
    println!("\n  All 10 TLS use cases work with full context selection!\n");

    // ====================================================================
    // Section 5: TlsConfig builder pattern — all use cases
    // ====================================================================
    println!("--- TlsConfig builder: all 10 use cases ---\n");

    for uc in use_cases {
        let config = TlsConfig::new().use_case(*uc);
        println!("  {:25} mode={:?}", format!("{:?}", uc), config.mode,);
    }
    println!("\n  TlsConfig builder works for all 10 use cases!\n");

    // ====================================================================
    // Section 6: TlsConfig builder — all 4 security levels
    // ====================================================================
    println!("--- TlsConfig builder: all 4 security levels ---\n");

    for (name, level) in levels {
        let config = TlsConfig::new().security_level(level.clone());
        println!("  {:10} mode={:?}", name, config.mode);
    }
    println!("\n  TlsConfig builder works for all 4 security levels!\n");

    // ====================================================================
    // Section 7: TlsConfig.validate() — all configurations pass
    // ====================================================================
    println!("--- TlsConfig.validate() for all use cases + levels ---\n");

    for uc in use_cases {
        let config = TlsConfig::new().use_case(*uc);
        config.validate().unwrap_or_else(|e| panic!("validate failed for {:?}: {}", uc, e));
    }
    for (name, level) in levels {
        let config = TlsConfig::new().security_level(level.clone());
        config.validate().unwrap_or_else(|e| panic!("validate failed for {}: {}", name, e));
    }
    println!("  All configurations pass validation!\n");

    // ====================================================================
    // Section 8: Constraint-based selection
    // ====================================================================
    println!("--- Constraints: override mode selection ---\n");

    // High security constraints allow PQ
    let hs = TlsConstraints::high_security();
    println!(
        "  high_security:  allows_pq={}, requires_classic={}",
        hs.allows_pq(),
        hs.requires_classic()
    );
    assert!(hs.allows_pq());
    assert!(!hs.requires_classic());

    // Maximum compatibility forces classic
    let mc = TlsConstraints::maximum_compatibility();
    println!(
        "  max_compat:     allows_pq={}, requires_classic={}",
        mc.allows_pq(),
        mc.requires_classic()
    );
    assert!(!mc.allows_pq());
    assert!(mc.requires_classic());

    // Constraint overrides use case recommendation
    let ctx_forced_classic = TlsContext::with_use_case(TlsUseCase::FinancialServices)
        .constraints(TlsConstraints::maximum_compatibility());
    let mode = TlsPolicyEngine::select_with_context(&ctx_forced_classic);
    println!("  FinancialServices + max_compat constraint -> {:?}", mode);
    assert_eq!(mode, TlsMode::Classic);

    // Quantum security level forces PQ even with use case
    let ctx_quantum =
        TlsContext::with_use_case(TlsUseCase::WebServer).security_level(SecurityLevel::Quantum);
    let mode = TlsPolicyEngine::select_with_context(&ctx_quantum);
    println!("  WebServer + Quantum level -> {:?}", mode);
    assert_eq!(mode, TlsMode::Pq);

    println!("\n  Constraints correctly override mode selection!\n");

    // ====================================================================
    // Section 9: Balanced selection (SecurityLevel x PerformancePreference)
    // ====================================================================
    println!("--- Balanced selection: SecurityLevel x PerformancePreference ---\n");

    let prefs: &[(&str, PerformancePreference)] = &[
        ("Speed", PerformancePreference::Speed),
        ("Memory", PerformancePreference::Memory),
        ("Balanced", PerformancePreference::Balanced),
    ];

    for (level_name, level) in levels {
        for (pref_name, pref) in prefs {
            let mode = TlsPolicyEngine::select_balanced(level.clone(), pref.clone());
            println!("  {:10} x {:10} -> {:?}", level_name, pref_name, mode);
        }
    }
    println!("\n  All SecurityLevel x PerformancePreference combinations work!\n");

    // ====================================================================
    // Section 10: PQ-only and Hybrid scheme selectors
    // ====================================================================
    println!("--- PQ-only and Hybrid scheme selectors ---\n");

    for (name, level) in levels {
        let pq = TlsPolicyEngine::select_pq_scheme(level.clone());
        let hybrid = TlsPolicyEngine::select_hybrid_scheme(level.clone());
        let pq_kex = TlsPolicyEngine::select_pq_kex(level.clone());
        let hybrid_kex = TlsPolicyEngine::select_hybrid_kex(level.clone());
        println!(
            "  {:10} PQ={:20} Hybrid={:30} PQ_KEX={:12} Hybrid_KEX={}",
            name, pq, hybrid, pq_kex, hybrid_kex
        );
    }
    println!("\n  All scheme selectors produce valid identifiers!\n");

    // ====================================================================
    // Section 11: Default constants
    // ====================================================================
    println!("--- Default TLS constants ---\n");
    println!("  Default scheme:    {}", TlsPolicyEngine::default_scheme());
    println!("  Default PQ scheme: {}", TlsPolicyEngine::default_pq_scheme());
    println!();

    println!(
        "=== All TLS policy engine tests passed! ({} use cases, {} security levels, {} performance prefs) ===",
        use_cases.len(),
        levels.len(),
        prefs.len(),
    );
}
