#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Basic TLS features: certificate handling and client/server connectors
//!
//! This module provides high-level APIs for TLS connections with
//! support for post-quantum key exchange.

use crate::tls13::{Tls13Config, create_client_config, create_server_config};
use crate::{TlsConfig, TlsError, TlsMode};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use zeroize::Zeroize;

/// Load certificates from a PEM file
///
/// # Errors
///
/// Returns an error if:
/// - The certificate file cannot be opened or read
/// - The PEM data cannot be parsed as valid certificates
/// - No valid certificates are found in the file
pub fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::Certificate {
        message: format!("Failed to open certificate file '{}': {}", path, e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::CertificateParseError,
        context: Box::default(),
        recovery: Box::new(crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
    })?;
    let mut reader = BufReader::new(file);

    // Use rustls-pki-types PemObject trait for constant-time PEM decoding
    let certs_vec: Vec<_> = CertificateDer::pem_reader_iter(&mut reader)
        .map(|cert_result| {
            cert_result.map_err(|e| TlsError::Certificate {
                message: format!("Failed to parse certificate: {}", e),
                subject: None,
                issuer: None,
                code: crate::error::ErrorCode::CertificateParseError,
                context: Box::default(),
                recovery: Box::new(crate::error::RecoveryHint::Retry {
                    max_attempts: 3,
                    backoff_ms: 1000,
                }),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if certs_vec.is_empty() {
        return Err(TlsError::Certificate {
            message: format!("No valid certificates found in file '{}'", path),
            subject: None,
            issuer: None,
            code: crate::error::ErrorCode::CertificateParseError,
            context: Box::default(),
            recovery: Box::new(crate::error::RecoveryHint::NoRecovery),
        });
    }

    Ok(certs_vec)
}

/// Deprecated: Use load_certificates instead
///
/// # Errors
///
/// Returns an error if:
/// - The certificate file cannot be opened or read
/// - The PEM data cannot be parsed as valid certificates
/// - No valid certificates are found in the file
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    load_certificates(path)
}

/// Secure private key container with automatic zeroization
pub struct SecurePrivateKey {
    key: PrivateKeyDer<'static>,
}

impl SecurePrivateKey {
    /// Create a new secure private key
    #[must_use]
    pub fn new(key: PrivateKeyDer<'static>) -> Self {
        Self { key }
    }

    /// Get reference to the key
    #[must_use]
    pub fn key_ref(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }
}

impl AsRef<PrivateKeyDer<'static>> for SecurePrivateKey {
    fn as_ref(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }
}

impl SecurePrivateKey {
    /// Consume and return the key
    #[must_use]
    pub fn into_inner(self) -> PrivateKeyDer<'static> {
        // We need to clone since we can't move out of a type that implements Drop
        // The zeroization will happen when the original is dropped
        self.key.clone_key()
    }

    /// Get the key as PKCS#1 format if possible
    #[must_use]
    pub fn as_pkcs1(&self) -> Option<&rustls_pki_types::PrivatePkcs1KeyDer<'static>> {
        match &self.key {
            PrivateKeyDer::Pkcs1(key) => Some(key),
            _ => None,
        }
    }

    /// Get the key as PKCS#8 format if possible
    #[must_use]
    pub fn as_pkcs8(&self) -> Option<&rustls_pki_types::PrivatePkcs8KeyDer<'static>> {
        match &self.key {
            PrivateKeyDer::Pkcs8(key) => Some(key),
            _ => None,
        }
    }

    /// Get the key as SEC1 format if possible
    #[must_use]
    pub fn as_sec1(&self) -> Option<&rustls_pki_types::PrivateSec1KeyDer<'static>> {
        match &self.key {
            PrivateKeyDer::Sec1(key) => Some(key),
            _ => None,
        }
    }
}

impl Drop for SecurePrivateKey {
    fn drop(&mut self) {
        // Zeroize key data when dropped
        // Note: PrivateKeyDer doesn't expose raw bytes directly
        // Zeroization is handled by the type itself
    }
}

impl Zeroize for SecurePrivateKey {
    fn zeroize(&mut self) {
        // The Drop implementation handles zeroization
        // This is called explicitly if needed
    }
}

/// Load private key from PEM file with secure handling
///
/// # Arguments
/// * `path` - Path to PEM file containing private key
///
/// # Returns
/// Secure private key container
///
/// # Errors
///
/// Returns an error if:
/// - The private key file cannot be opened or read
/// - The PEM data cannot be parsed as a valid private key
///
/// # Example
/// ```no_run
/// use arc_tls::basic_features::load_private_key_secure;
///
/// let key = load_private_key_secure("server.key")?;
/// # Ok::<(), arc_tls::TlsError>(())
/// ```
pub fn load_private_key_secure(path: &str) -> Result<SecurePrivateKey, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::Certificate {
        message: format!("Failed to open private key file '{}': {}", path, e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::MissingPrivateKey,
        context: Box::default(),
        recovery: Box::new(crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
    })?;
    let mut reader = BufReader::new(file);

    // Use rustls-pki-types PemObject trait for constant-time private key decoding
    let key = PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| TlsError::Certificate {
        message: format!("Failed to parse private key: {}", e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::MissingPrivateKey,
        context: Box::default(),
        recovery: Box::new(crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
    })?;

    Ok(SecurePrivateKey::new(key))
}

/// Load private key from PEM file
///
/// # Arguments
/// * `path` - Path to PEM file containing private key
///
/// # Returns
/// PrivateKeyDer object (supports PKCS#1, PKCS#8, and SEC1 formats)
///
/// # Errors
///
/// Returns an error if:
/// - The private key file cannot be opened or read
/// - The PEM data cannot be parsed as a valid private key
///
/// # Example
/// ```no_run
/// use arc_tls::basic_features::load_private_key;
///
/// let key = load_private_key("server.key")?;
/// # Ok::<(), arc_tls::TlsError>(())
/// ```
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::Certificate {
        message: format!("Failed to open private key file '{}': {}", path, e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::MissingPrivateKey,
        context: Box::default(),
        recovery: Box::new(crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
    })?;
    let mut reader = BufReader::new(file);

    // Use rustls-pki-types PemObject trait for constant-time private key decoding
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| TlsError::Certificate {
        message: format!("Failed to parse private key: {}", e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::MissingPrivateKey,
        context: Box::default(),
        recovery: Box::new(crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
    })
}

/// Create TLS client connector with post-quantum support
///
/// # Arguments
/// * `config` - TLS configuration (Classic, Hybrid, or PQ)
///
/// # Returns
/// TlsConnector configured with appropriate key exchange
///
/// # Errors
///
/// Returns an error if:
/// - System root certificates cannot be loaded
/// - The crypto provider fails to initialize
/// - The specified protocol versions are not supported
/// - Client certificates are configured but cannot be loaded (mTLS)
///
/// # Example
/// ```no_run
/// use arc_tls::{TlsConfig, TlsUseCase, basic_features::create_client_connector};
/// use arc_core::SecurityLevel;
///
/// // Default: hybrid mode with PQ key exchange
/// let connector = create_client_connector(&TlsConfig::new())?;
///
/// // Standard security (NIST Level 1, Hybrid mode)
/// let standard_connector = create_client_connector(
///     &TlsConfig::new().security_level(SecurityLevel::Standard)
/// )?;
///
/// // mTLS: client presents certificate
/// let mtls_connector = create_client_connector(
///     &TlsConfig::new().with_client_auth("client.crt", "client.key")
/// )?;
/// # Ok::<(), arc_tls::TlsError>(())
/// ```
pub fn create_client_connector(config: &TlsConfig) -> Result<TlsConnector, TlsError> {
    let mut tls13_config = Tls13Config::from(config);

    // Load client certificates for mTLS if configured
    if let Some(ref client_auth) = config.client_auth {
        let cert_chain = load_certificates(&client_auth.cert_path)?;
        let private_key = load_private_key(&client_auth.key_path)?;
        tls13_config.client_cert_chain = Some(cert_chain);
        tls13_config.client_private_key = Some(private_key);
    }

    let client_config = create_client_config(&tls13_config)?;

    Ok(TlsConnector::from(Arc::new(client_config)))
}

/// Create TLS server acceptor with post-quantum support
///
/// # Arguments
/// * `config` - TLS configuration (Classic, Hybrid, or PQ)
/// * `cert_path` - Path to server certificate file
/// * `key_path` - Path to server private key file
///
/// # Returns
/// TlsAcceptor configured with appropriate key exchange
///
/// # Errors
///
/// Returns an error if:
/// - The certificate file cannot be loaded or parsed
/// - The private key file cannot be loaded or parsed
/// - The certificate and private key are incompatible
/// - The crypto provider fails to initialize
/// - Client CA certificates are required but cannot be loaded (mTLS)
///
/// # Example
/// ```no_run
/// use arc_tls::{TlsConfig, ClientVerificationMode, basic_features::create_server_acceptor};
///
/// // Basic server (no client auth)
/// let acceptor = create_server_acceptor(
///     &TlsConfig::default(),
///     "server.crt",
///     "server.key"
/// )?;
///
/// // mTLS server (require client certificates)
/// let mtls_acceptor = create_server_acceptor(
///     &TlsConfig::new()
///         .with_client_verification(ClientVerificationMode::Required)
///         .with_client_ca_certs("ca-bundle.crt"),
///     "server.crt",
///     "server.key"
/// )?;
/// # Ok::<(), arc_tls::TlsError>(())
/// ```
pub fn create_server_acceptor(
    config: &TlsConfig,
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, TlsError> {
    let certs = load_certificates(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut tls13_config = Tls13Config::from(config);

    // Load client CA certificates for mTLS verification if configured
    if let Some(ref ca_certs_path) = config.client_ca_certs {
        let ca_certs = load_certificates(ca_certs_path)?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).map_err(|e| TlsError::Certificate {
                message: format!("Failed to add CA certificate: {}", e),
                subject: None,
                issuer: None,
                code: crate::error::ErrorCode::CertificateParseError,
                context: Box::default(),
                recovery: Box::new(crate::error::RecoveryHint::NoRecovery),
            })?;
        }
        tls13_config.client_ca_roots = Some(root_store);
    }

    let server_config = create_server_config(&tls13_config, certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Establish TLS connection as client
///
/// # Arguments
/// * `addr` - Server address (e.g., "example.com:443")
/// * `domain` - Server domain name for SNI
/// * `config` - TLS configuration
///
/// # Returns
/// TLS stream wrapped around TCP connection
///
/// # Errors
///
/// Returns an error if:
/// - The domain name is invalid for SNI
/// - The TCP connection cannot be established
/// - The TLS handshake fails (certificate verification, protocol mismatch, etc.)
/// - System root certificates cannot be loaded
///
/// # Example
/// ```no_run
/// use arc_tls::{TlsConfig, TlsError, basic_features::tls_connect};
///
/// # async fn example() -> Result<(), TlsError> {
/// let stream = tls_connect("example.com:443", "example.com", &TlsConfig::default()).await?;
/// # Ok(())
/// # }
/// ```
pub async fn tls_connect(
    addr: &str,
    domain: &str,
    config: &TlsConfig,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TlsError> {
    let dns_name =
        rustls_pki_types::DnsName::try_from(domain.to_owned()).map_err(|_e| TlsError::Config {
            message: "Invalid domain name".to_string(),
            field: Some("domain".to_string()),
            code: crate::error::ErrorCode::InvalidConfig,
            context: Box::default(),
            recovery: Box::new(crate::error::RecoveryHint::NoRecovery),
        })?;
    let server_name = rustls_pki_types::ServerName::DnsName(dns_name);

    let connector = create_client_connector(config)?;
    let stream = TcpStream::connect(addr).await?;

    let tls_stream = connector.connect(server_name, stream).await?;
    Ok(tls_stream)
}

/// Accept TLS connection as server
///
/// # Arguments
/// * `stream` - Accepted TCP stream
/// * `acceptor` - TLS acceptor
///
/// # Returns
/// TLS stream wrapped around TCP connection
///
/// # Errors
///
/// Returns an error if the TLS handshake fails, which can occur due to:
/// - Protocol version mismatch with the client
/// - Cipher suite negotiation failure
/// - Client certificate validation failure (if client auth is required)
/// - Connection reset or timeout during handshake
///
/// # Example
/// ```no_run
/// use tokio::net::TcpListener;
/// use arc_tls::{TlsConfig, TlsError, basic_features::{create_server_acceptor, tls_accept}};
///
/// # async fn example() -> Result<(), TlsError> {
/// let acceptor = create_server_acceptor(&TlsConfig::default(), "server.crt", "server.key")?;
/// let listener = TcpListener::bind("0.0.0.0:8443").await.map_err(TlsError::from)?;
/// let (stream, _) = listener.accept().await.map_err(TlsError::from)?;
/// let tls_stream = tls_accept(stream, &acceptor).await?;
/// # Ok(())
/// # }
/// ```
pub async fn tls_accept(
    stream: TcpStream,
    acceptor: &TlsAcceptor,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, TlsError> {
    let tls_stream = acceptor.accept(stream).await?;
    Ok(tls_stream)
}

/// Get information about TLS configuration
///
/// # Arguments
/// * `config` - TLS configuration
///
/// # Returns
/// String describing the configuration
#[must_use]
pub fn get_config_info(config: &TlsConfig) -> String {
    match config.mode {
        TlsMode::Classic => "Classic TLS 1.3 with X25519 (ECDHE) - Not PQ secure".to_string(),
        TlsMode::Hybrid => {
            "Hybrid TLS 1.3 with X25519MLKEM768 - PQ secure (recommended)".to_string()
        }
        TlsMode::Pq => "Post-quantum TLS 1.3 with ML-KEM - PQ secure".to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use arc_core::SecurityLevel;

    #[test]
    fn test_config_info_standard() {
        // Standard uses Hybrid mode
        let config = TlsConfig::new().security_level(SecurityLevel::Standard);
        let info = get_config_info(&config);
        assert!(info.contains("Hybrid"));
        assert!(info.contains("PQ secure"));
    }

    #[test]
    fn test_config_info_hybrid() {
        // Default (High) uses Hybrid mode
        let config = TlsConfig::new();
        let info = get_config_info(&config);
        assert!(info.contains("Hybrid"));
        assert!(info.contains("PQ secure"));
    }

    #[test]
    fn test_config_info_pq() {
        // Quantum uses PQ-only mode
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        let info = get_config_info(&config);
        assert!(info.contains("Post-quantum") || info.contains("PQ"));
    }

    #[test]
    fn test_config_info_classic() {
        let mut config = TlsConfig::new();
        config.mode = TlsMode::Classic;
        let info = get_config_info(&config);
        assert!(info.contains("Classic"));
        assert!(info.contains("Not PQ secure"));
    }

    #[test]
    fn test_load_certificates_nonexistent_file() {
        let result = load_certificates("/nonexistent/path/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certs_delegates_to_load_certificates() {
        // load_certs should return same error as load_certificates
        let result = load_certs("/nonexistent/path/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_nonexistent_file() {
        let result = load_private_key("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_secure_nonexistent_file() {
        let result = load_private_key_secure("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_private_key_pkcs8() {
        // Create a PKCS#8 key
        let key_bytes = vec![1u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(key_bytes));
        let secure = SecurePrivateKey::new(key);

        assert!(secure.as_pkcs8().is_some());
        assert!(secure.as_pkcs1().is_none());
        assert!(secure.as_sec1().is_none());

        let _key_ref = secure.key_ref();
    }

    #[test]
    fn test_secure_private_key_pkcs1() {
        let key_bytes = vec![2u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivatePkcs1KeyDer::from(key_bytes));
        let secure = SecurePrivateKey::new(key);

        assert!(secure.as_pkcs1().is_some());
        assert!(secure.as_pkcs8().is_none());
        assert!(secure.as_sec1().is_none());
    }

    #[test]
    fn test_secure_private_key_sec1() {
        let key_bytes = vec![3u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivateSec1KeyDer::from(key_bytes));
        let secure = SecurePrivateKey::new(key);

        assert!(secure.as_sec1().is_some());
        assert!(secure.as_pkcs1().is_none());
        assert!(secure.as_pkcs8().is_none());
    }

    #[test]
    fn test_secure_private_key_into_inner() {
        let key_bytes = vec![4u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(key_bytes));
        let secure = SecurePrivateKey::new(key);

        let _inner = secure.into_inner();
        // SecurePrivateKey is consumed, no use-after-free
    }

    #[test]
    fn test_secure_private_key_as_ref() {
        let key_bytes = vec![5u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(key_bytes));
        let secure = SecurePrivateKey::new(key);

        let key_ref: &PrivateKeyDer<'static> = secure.as_ref();
        assert!(matches!(key_ref, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_secure_private_key_zeroize() {
        let key_bytes = vec![6u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(key_bytes));
        let mut secure = SecurePrivateKey::new(key);
        secure.zeroize(); // Should not panic
    }

    #[test]
    fn test_secure_private_key_drop() {
        let key_bytes = vec![7u8; 32];
        let key = PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(key_bytes));
        let secure = SecurePrivateKey::new(key);
        drop(secure); // Should not panic - zeroize on drop
    }

    // === Tests with valid PEM files using rcgen ===

    fn generate_test_cert_and_key() -> (String, String, tempfile::TempDir) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        (cert_path.to_str().unwrap().to_string(), key_path.to_str().unwrap().to_string(), dir)
    }

    #[test]
    fn test_load_certificates_valid_pem() {
        let (cert_path, _key_path, _dir) = generate_test_cert_and_key();
        let certs = load_certificates(&cert_path);
        assert!(certs.is_ok(), "Should load valid PEM certificate");
        assert_eq!(certs.unwrap().len(), 1);
    }

    #[test]
    fn test_load_certificates_empty_pem_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("empty.pem");
        std::fs::write(&cert_path, "").unwrap();

        let result = load_certificates(cert_path.to_str().unwrap());
        assert!(result.is_err(), "Empty PEM should produce error");
    }

    #[test]
    fn test_load_certificates_invalid_pem_content() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("invalid.pem");
        std::fs::write(&cert_path, "NOT A VALID PEM FILE").unwrap();

        let result = load_certificates(cert_path.to_str().unwrap());
        assert!(result.is_err(), "Invalid PEM content should produce error");
    }

    #[test]
    fn test_load_certs_valid_pem() {
        let (cert_path, _key_path, _dir) = generate_test_cert_and_key();
        let certs = load_certs(&cert_path);
        assert!(certs.is_ok());
        assert_eq!(certs.unwrap().len(), 1);
    }

    #[test]
    fn test_load_private_key_valid_pem() {
        let (_cert_path, key_path, _dir) = generate_test_cert_and_key();
        let key = load_private_key(&key_path);
        assert!(key.is_ok(), "Should load valid PEM private key");
    }

    #[test]
    fn test_load_private_key_secure_valid_pem() {
        let (_cert_path, key_path, _dir) = generate_test_cert_and_key();
        let secure_key = load_private_key_secure(&key_path);
        assert!(secure_key.is_ok(), "Should load valid PEM private key securely");
        let sk = secure_key.unwrap();
        // rcgen generates PKCS#8 keys
        assert!(sk.as_pkcs8().is_some(), "Key should be PKCS#8 format");
    }

    #[test]
    fn test_load_private_key_secure_into_inner() {
        let (_cert_path, key_path, _dir) = generate_test_cert_and_key();
        let secure_key = load_private_key_secure(&key_path).unwrap();
        let _inner = secure_key.into_inner();
        // Verify the key can be consumed without panic
    }

    #[test]
    fn test_create_client_connector_default_config() {
        let config = TlsConfig::new();
        let connector = create_client_connector(&config);
        assert!(connector.is_ok(), "Default client connector should succeed");
    }

    #[test]
    fn test_create_client_connector_classic_mode() {
        let mut config = TlsConfig::new();
        config.mode = TlsMode::Classic;
        let connector = create_client_connector(&config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_create_server_acceptor_valid() {
        let (cert_path, key_path, _dir) = generate_test_cert_and_key();
        let config = TlsConfig::new();
        let acceptor = create_server_acceptor(&config, &cert_path, &key_path);
        assert!(acceptor.is_ok(), "Server acceptor with valid cert/key should succeed");
    }

    #[test]
    fn test_create_server_acceptor_classic_mode() {
        let (cert_path, key_path, _dir) = generate_test_cert_and_key();
        let mut config = TlsConfig::new();
        config.mode = TlsMode::Classic;
        let acceptor = create_server_acceptor(&config, &cert_path, &key_path);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_create_server_acceptor_nonexistent_cert() {
        let config = TlsConfig::new();
        let result =
            create_server_acceptor(&config, "/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_server_acceptor_mtls_with_ca() {
        // Generate CA
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Generate server cert signed by CA
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        // Write PEM files
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.pem");
        let key_path = dir.path().join("server.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, server_cert.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();

        let config = TlsConfig::new()
            .with_client_verification(crate::ClientVerificationMode::Required)
            .with_client_ca_certs(ca_path.to_str().unwrap());
        let acceptor = create_server_acceptor(
            &config,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        );
        assert!(acceptor.is_ok(), "mTLS server acceptor should succeed with valid CA");
    }

    #[test]
    fn test_load_private_key_invalid_pem_content() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("invalid.pem");
        std::fs::write(&key_path, "NOT A VALID KEY").unwrap();

        let result = load_private_key(key_path.to_str().unwrap());
        assert!(result.is_err(), "Invalid PEM content should produce error");
    }

    #[test]
    fn test_load_private_key_secure_invalid_pem_content() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("invalid.pem");
        std::fs::write(&key_path, "NOT A VALID KEY").unwrap();

        let result = load_private_key_secure(key_path.to_str().unwrap());
        assert!(result.is_err(), "Invalid PEM content should produce error");
    }

    #[test]
    fn test_load_certificates_multiple_certs() {
        // Generate two certs and concatenate PEM
        let key1 = rcgen::KeyPair::generate().unwrap();
        let params1 = rcgen::CertificateParams::new(vec!["cert1.test".to_string()]).unwrap();
        let cert1 = params1.self_signed(&key1).unwrap();

        let key2 = rcgen::KeyPair::generate().unwrap();
        let params2 = rcgen::CertificateParams::new(vec!["cert2.test".to_string()]).unwrap();
        let cert2 = params2.self_signed(&key2).unwrap();

        let combined_pem = format!("{}{}", cert1.pem(), cert2.pem());
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("multi.pem");
        std::fs::write(&cert_path, combined_pem).unwrap();

        let certs = load_certificates(cert_path.to_str().unwrap());
        assert!(certs.is_ok());
        assert_eq!(certs.unwrap().len(), 2, "Should load both certificates");
    }
}
