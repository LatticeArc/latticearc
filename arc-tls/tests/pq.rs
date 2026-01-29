#![deny(unsafe_code)]
// Test files use unwrap() for simplicity
#![allow(clippy::unwrap_used)]

//! PQ key exchange tests

#[cfg(test)]
mod pq_tests {
    use arc_tls::{TlsMode, pq_key_exchange::*};

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
        // PQ is always available via rustls-post-quantum
        let available = is_pq_available();
        assert!(available);
    }

    #[test]
    fn test_custom_hybrid_availability() {
        // Custom hybrid is always available
        let available = is_custom_hybrid_available();
        assert!(available);
    }
}
