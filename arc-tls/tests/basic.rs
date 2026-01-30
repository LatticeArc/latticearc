#![deny(unsafe_code)]
// Test files use unwrap() and panic for assertions
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
// Tests may use wildcard matches for brevity
#![allow(clippy::wildcard_enum_match_arm)]

//! Basic TLS connection tests

#[cfg(test)]
mod basic_tests {
    use arc_tls::basic_features::*;
    use arc_tls::{ErrorCode, TlsConfig, TlsError};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_client_connector_creation() {
        let config = TlsConfig::default();
        let connector = create_client_connector(&config);
        assert!(connector.is_ok());
    }

    #[tokio::test]
    async fn test_server_acceptor_creation() {
        let config = TlsConfig::default();
        // This would need actual cert files for full test
        // For now, test the function signature and error handling
        let result = create_server_acceptor(&config, "nonexistent.crt", "nonexistent.key");
        assert!(result.is_err()); // Should fail with missing files
    }

    #[test]
    fn test_load_certificates_nonexistent_file() {
        let result = load_certificates("nonexistent.crt");
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::CertificateParseError);
            }
            _ => panic!("Expected Certificate error"),
        }
    }

    #[test]
    fn test_load_private_key_nonexistent_file() {
        let result = load_private_key("nonexistent.key");
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::MissingPrivateKey);
            }
            _ => panic!("Expected Certificate error"),
        }
    }

    #[test]
    fn test_load_private_key_secure_nonexistent_file() {
        let result = load_private_key_secure("nonexistent.key");
        assert!(result.is_err());

        if let Err(err) = result {
            match err {
                TlsError::Certificate { code, .. } => {
                    assert_eq!(code, ErrorCode::MissingPrivateKey);
                }
                _ => panic!("Expected Certificate error"),
            }
        }
    }

    #[test]
    fn test_load_certificates_invalid_pem() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "INVALID PEM DATA").unwrap();

        let result = load_certificates(temp_file.path().to_str().unwrap());
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::CertificateParseError);
            }
            _ => panic!("Expected Certificate error"),
        }
    }

    #[test]
    fn test_load_private_key_invalid_pem() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "INVALID PEM DATA").unwrap();

        let result = load_private_key(temp_file.path().to_str().unwrap());
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Certificate { code, .. } => {
                assert_eq!(code, ErrorCode::MissingPrivateKey);
            }
            _ => panic!("Expected Certificate error"),
        }
    }

    #[test]
    fn test_secure_private_key_methods() {
        // Test with a dummy PKCS#1 key (this won't be cryptographically valid)
        let dummy_key_data = vec![0x30u8; 100]; // Dummy ASN.1 structure
        let pkcs1_key = rustls_pki_types::PrivatePkcs1KeyDer::from(dummy_key_data);
        let secure_key = PrivateKeyDer::Pkcs1(pkcs1_key);
        let secure_container = SecurePrivateKey::new(secure_key);

        // Test access methods
        assert!(secure_container.as_pkcs1().is_some());
        assert!(secure_container.as_pkcs8().is_none());
        assert!(secure_container.as_sec1().is_none());

        // Test into_inner
        let _extracted_key = secure_container.into_inner();
    }

    #[test]
    fn test_config_info_all_modes() {
        use arc_core::SecurityLevel;

        // Standard still uses Hybrid mode (only use cases like IoT use Classic)
        let standard_config = TlsConfig::new().security_level(SecurityLevel::Standard);
        let standard_info = get_config_info(&standard_config);
        assert!(standard_info.contains("Hybrid"));

        let hybrid_config = TlsConfig::new();
        let hybrid_info = get_config_info(&hybrid_config);
        assert!(hybrid_info.contains("Hybrid"));

        let pq_config = TlsConfig::new().security_level(SecurityLevel::Maximum);
        let pq_info = get_config_info(&pq_config);
        assert!(pq_info.contains("Post-quantum") || pq_info.contains("PQ"));
    }

    #[test]
    fn test_tls_config_with_options() {
        let config = TlsConfig::default().with_tracing().with_fallback(false);

        assert!(config.enable_tracing);
        assert!(!config.enable_fallback);
    }

    #[test]
    fn test_private_key_der_variants() {
        // Test that we can handle different private key formats

        // PKCS#1 format
        let pkcs1_data = vec![0x30u8; 50];
        let pkcs1_key = rustls_pki_types::PrivatePkcs1KeyDer::from(pkcs1_data);
        let pkcs1_der = PrivateKeyDer::Pkcs1(pkcs1_key);
        assert!(matches!(pkcs1_der, PrivateKeyDer::Pkcs1(_)));

        // PKCS#8 format
        let pkcs8_data = vec![0x30u8; 60];
        let pkcs8_key = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_data);
        let pkcs8_der = PrivateKeyDer::Pkcs8(pkcs8_key);
        assert!(matches!(pkcs8_der, PrivateKeyDer::Pkcs8(_)));

        // SEC1 format
        let sec1_data = vec![0x30u8; 40];
        let sec1_key = rustls_pki_types::PrivateSec1KeyDer::from(sec1_data);
        let sec1_der = PrivateKeyDer::Sec1(sec1_key);
        assert!(matches!(sec1_der, PrivateKeyDer::Sec1(_)));
    }

    #[test]
    fn test_certificate_der_creation() {
        // Test that CertificateDer can be created from byte data
        let cert_data = vec![0x30u8; 100]; // Dummy X.509 certificate
        let cert = CertificateDer::from(cert_data);

        // The certificate should contain the data
        assert!(!cert.is_empty());
    }

    #[tokio::test]
    async fn test_tls_connect_invalid_domain() {
        let config = TlsConfig::default();
        let result =
            tls_connect("invalid.domain.example:443", "invalid.domain.example", &config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tls_connect_invalid_domain_name_format() {
        let config = TlsConfig::default();
        let result = tls_connect("example.com:443", "", &config).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            TlsError::Config { code, .. } => {
                assert_eq!(code, ErrorCode::InvalidConfig);
            }
            _ => panic!("Expected Config error"),
        }
    }
}
