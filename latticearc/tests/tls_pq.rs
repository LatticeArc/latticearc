#![deny(unsafe_code)]
// Test files use unwrap() for simplicity
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

//! PQ key exchange integration tests
//!
//! Tests for native rustls PQ key exchange (v0.23.37+):
//! - Provider creation for all mode combinations
//! - PQ preference ordering verification
//! - Native PQ group availability
//! - No dependency on rustls-post-quantum

#[cfg(test)]
mod pq_tests {
    use latticearc::tls::{TlsMode, pq_key_exchange::*};

    #[test]
    fn test_pq_kex_info_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_pq_kex_info_classical() {
        let info = get_kex_info(TlsMode::Classic, PqKexMode::Classical);
        assert_eq!(info.method, "X25519 (ECDHE)");
        assert!(!info.is_pq_secure);
        assert_eq!(info.ss_size, 32);
    }

    #[test]
    fn test_get_kex_provider_pq() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_classical() {
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_pq_availability() {
        // PQ is always available via rustls native support
        let available = is_pq_available();
        assert!(available);
    }

    #[test]
    fn test_custom_hybrid_availability() {
        // Custom hybrid is always available
        let available = is_custom_hybrid_available();
        assert!(available);
    }

    // ========================================================================
    // v0.3.3: Native PQ key exchange tests (rustls-post-quantum removed)
    // ========================================================================

    #[test]
    fn test_hybrid_provider_has_pq_groups_first() {
        // Verify PQ/hybrid groups are sorted before classical-only groups
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)
            .expect("Hybrid provider should be available");

        let group_names: Vec<String> =
            provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

        // First group must contain MLKEM (PQ preference sorting)
        assert!(
            group_names[0].contains("MLKEM"),
            "First kx_group must be PQ, got: {:?}",
            group_names[0]
        );

        // All MLKEM groups before all non-MLKEM groups
        let last_mlkem_idx =
            group_names.iter().rposition(|n| n.contains("MLKEM")).expect("Must have MLKEM groups");
        let first_classical_idx = group_names
            .iter()
            .position(|n| !n.contains("MLKEM"))
            .expect("Must have classical groups");

        assert!(
            last_mlkem_idx < first_classical_idx,
            "PQ groups must precede classical groups: {group_names:?}"
        );
    }

    #[test]
    fn test_pq_mode_provider_has_pq_groups_first() {
        // Same ordering guarantee for PQ-only mode
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq)
            .expect("PQ provider should be available");

        let first_name = format!("{:?}", provider.kx_groups[0].name());
        assert!(
            first_name.contains("MLKEM"),
            "First group in PQ mode must be MLKEM, got: {first_name}"
        );
    }

    #[test]
    fn test_classic_provider_no_pq_reordering() {
        // Classic mode should use default_provider() without PQ sorting
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical)
            .expect("Classic provider should be available");

        // Should have at least X25519
        let group_names: Vec<String> =
            provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

        assert!(
            group_names.iter().any(|n| n.contains("X25519")),
            "Classic provider must include X25519"
        );
    }

    #[test]
    fn test_native_x25519mlkem768_available() {
        // Verify X25519MLKEM768 is natively available without rustls-post-quantum
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)
            .expect("Provider should be available");

        let has_hybrid_pq = provider.kx_groups.iter().any(|g| {
            let name = format!("{:?}", g.name());
            name.contains("X25519MLKEM768")
        });

        assert!(
            has_hybrid_pq,
            "X25519MLKEM768 must be natively available in rustls default_provider()"
        );
    }

    #[test]
    fn test_all_modes_produce_non_empty_providers() {
        // Every (TlsMode, PqKexMode) combination must produce a provider with groups
        let modes = [
            (TlsMode::Hybrid, PqKexMode::RustlsPq),
            (TlsMode::Hybrid, PqKexMode::CustomHybrid),
            (TlsMode::Hybrid, PqKexMode::Classical),
            (TlsMode::Pq, PqKexMode::RustlsPq),
            (TlsMode::Pq, PqKexMode::CustomHybrid),
            (TlsMode::Classic, PqKexMode::Classical),
            (TlsMode::Classic, PqKexMode::RustlsPq),
        ];

        for (tls_mode, kex_mode) in modes {
            let provider = get_kex_provider(tls_mode, kex_mode).unwrap();
            assert!(
                !provider.kx_groups.is_empty(),
                "Provider for {tls_mode:?}/{kex_mode:?} must have key exchange groups"
            );
        }
    }

    #[test]
    fn test_kex_info_consistency_with_provider() {
        // KexInfo claims X25519MLKEM768 for Hybrid+RustlsPq — verify the provider
        // actually contains that group
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq).unwrap();

        let group_names: Vec<String> =
            provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

        // The method reported by KexInfo should exist in the provider's groups
        assert!(
            group_names.iter().any(|n| n.contains(&info.method)),
            "KexInfo method '{}' not found in provider groups: {group_names:?}",
            info.method
        );
    }

    #[test]
    fn test_hybrid_provider_includes_classical_fallback() {
        // Hybrid mode must include classical groups for backward compatibility
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)
            .expect("Provider should be available");

        let has_x25519 = provider.kx_groups.iter().any(|g| {
            let name = format!("{:?}", g.name());
            name == "X25519"
        });

        assert!(has_x25519, "Hybrid provider must include X25519 for classical fallback");
    }
}
