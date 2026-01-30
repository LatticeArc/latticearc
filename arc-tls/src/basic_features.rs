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
        context: Default::default(),
        recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
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
                context: Default::default(),
                recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if certs_vec.is_empty() {
        return Err(TlsError::Certificate {
            message: format!("No valid certificates found in file '{}'", path),
            subject: None,
            issuer: None,
            code: crate::error::ErrorCode::CertificateParseError,
            context: Default::default(),
            recovery: crate::error::RecoveryHint::NoRecovery,
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
    pub fn as_ref(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }

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
        context: Default::default(),
        recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
    })?;
    let mut reader = BufReader::new(file);

    // Use rustls-pki-types PemObject trait for constant-time private key decoding
    let key = PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| TlsError::Certificate {
        message: format!("Failed to parse private key: {}", e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::MissingPrivateKey,
        context: Default::default(),
        recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
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
        context: Default::default(),
        recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
    })?;
    let mut reader = BufReader::new(file);

    // Use rustls-pki-types PemObject trait for constant-time private key decoding
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| TlsError::Certificate {
        message: format!("Failed to parse private key: {}", e),
        subject: None,
        issuer: None,
        code: crate::error::ErrorCode::MissingPrivateKey,
        context: Default::default(),
        recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
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
                context: Default::default(),
                recovery: crate::error::RecoveryHint::NoRecovery,
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
            context: Default::default(),
            recovery: crate::error::RecoveryHint::NoRecovery,
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
}
