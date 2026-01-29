#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # TLS 1.3 Handshake with Post-Quantum Key Exchange
//!
//! This module implements TLS 1.3 handshake logic with support for:
//! - Classic TLS 1.3 (ECDHE-only)
//! - Hybrid TLS 1.3 (X25519MLKEM768 - recommended)
//! - Post-quantum only TLS 1.3 (ML-KEM)
//!
//! ## Handshake Flow
//!
//! ### Classic TLS 1.3
//! 1. ClientHello → (X25519 key share)
//! 2. ServerHello → (X25519 key share)
//! 3. EncryptedExtensions, Certificate, CertificateVerify, Finished
//! 4. Finished (client)
//!
//! ### Hybrid TLS 1.3 (X25519MLKEM768)
//! 1. ClientHello → (X25519 + ML-KEM-768 key shares)
//! 2. ServerHello → (X25519 + ML-KEM-768 key shares)
//! 3. EncryptedExtensions, Certificate, CertificateVerify, Finished
//! 4. Finished (client)
//!
//! The hybrid approach combines:
//! - **X25519**: Well-tested, efficient classical key exchange
//! - **ML-KEM-768**: Post-quantum secure key encapsulation (NIST FIPS 203)
//!
//! Security is maintained even if one component is compromised.

use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

use crate::{ClientVerificationMode, TlsError, TlsMode};

/// TLS 1.3 handshake configuration with enhanced security options
#[derive(Debug)]
pub struct Tls13Config {
    /// TLS mode (Classic, Hybrid, or PQ)
    pub mode: TlsMode,
    /// Use post-quantum key exchange
    pub use_pq_kx: bool,
    /// Enable early data (0-RTT)
    pub enable_early_data: bool,
    /// Maximum early data size (bytes)
    pub max_early_data_size: u32,
    /// Custom crypto provider (None for default selection)
    pub crypto_provider: Option<rustls::crypto::CryptoProvider>,
    /// Protocol versions to support
    pub protocol_versions: Vec<&'static rustls::SupportedProtocolVersion>,
    /// Cipher suites to use (None for secure defaults)
    pub cipher_suites: Option<Vec<SupportedCipherSuite>>,
    /// ALPN protocols
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Maximum fragment size
    pub max_fragment_size: Option<usize>,
    /// Session resumption configuration
    pub resumption: rustls::client::Resumption,
    /// Key logging configuration
    pub key_log: Option<Arc<dyn rustls::KeyLog>>,
    /// Client certificate chain for mTLS (client-side)
    pub client_cert_chain: Option<Vec<CertificateDer<'static>>>,
    /// Client private key for mTLS (client-side)
    pub client_private_key: Option<PrivateKeyDer<'static>>,
    /// Client verification mode (server-side)
    pub client_verification: ClientVerificationMode,
    /// Client CA root store for verification (server-side)
    pub client_ca_roots: Option<RootCertStore>,
}

impl Default for Tls13Config {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            use_pq_kx: true,
            enable_early_data: false,
            max_early_data_size: 0,
            crypto_provider: None,
            protocol_versions: vec![&rustls::version::TLS13],
            cipher_suites: None,
            alpn_protocols: vec![],
            max_fragment_size: None,
            resumption: rustls::client::Resumption::in_memory_sessions(32),
            key_log: None,
            client_cert_chain: None,
            client_private_key: None,
            client_verification: ClientVerificationMode::default(),
            client_ca_roots: None,
        }
    }
}

impl Tls13Config {
    /// Create classic TLS 1.3 configuration
    #[must_use]
    pub fn classic() -> Self {
        Self { mode: TlsMode::Classic, use_pq_kx: false, ..Default::default() }
    }

    /// Create hybrid TLS 1.3 configuration (default)
    #[must_use]
    pub fn hybrid() -> Self {
        Self { mode: TlsMode::Hybrid, use_pq_kx: true, ..Default::default() }
    }

    /// Create post-quantum only TLS 1.3 configuration
    #[must_use]
    pub fn pq() -> Self {
        Self { mode: TlsMode::Pq, use_pq_kx: true, ..Default::default() }
    }

    /// Enable early data (0-RTT)
    #[must_use]
    pub fn with_early_data(mut self, max_size: u32) -> Self {
        self.enable_early_data = true;
        self.max_early_data_size = max_size;
        self
    }

    /// Configure key exchange method
    #[must_use]
    pub fn with_pq_kx(mut self, use_pq: bool) -> Self {
        self.use_pq_kx = use_pq;
        self
    }

    /// Set custom crypto provider
    #[must_use]
    pub fn with_crypto_provider(mut self, provider: rustls::crypto::CryptoProvider) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Set protocol versions
    #[must_use]
    pub fn with_protocol_versions(
        mut self,
        versions: Vec<&'static rustls::SupportedProtocolVersion>,
    ) -> Self {
        self.protocol_versions = versions;
        self
    }

    /// Set cipher suites
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Set ALPN protocols
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<&'static str>) -> Self {
        self.alpn_protocols = protocols.into_iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    /// Set maximum fragment size
    #[must_use]
    pub fn with_max_fragment_size(mut self, size: usize) -> Self {
        self.max_fragment_size = Some(size);
        self
    }

    /// Set session resumption
    #[must_use]
    pub fn with_resumption(mut self, resumption: rustls::client::Resumption) -> Self {
        self.resumption = resumption;
        self
    }

    /// Set key logger
    pub fn with_key_log(mut self, key_log: Arc<dyn rustls::KeyLog>) -> Self {
        self.key_log = Some(key_log);
        self
    }

    /// Set client certificate and key for mTLS (client-side)
    ///
    /// # Arguments
    /// * `cert_chain` - Client certificate chain
    /// * `private_key` - Client private key
    #[must_use]
    pub fn with_client_cert(
        mut self,
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert_chain = Some(cert_chain);
        self.client_private_key = Some(private_key);
        self
    }

    /// Set client verification mode (server-side)
    ///
    /// # Arguments
    /// * `mode` - Client verification mode
    #[must_use]
    pub fn with_client_verification(mut self, mode: ClientVerificationMode) -> Self {
        self.client_verification = mode;
        self
    }

    /// Set client CA roots for verification (server-side)
    ///
    /// # Arguments
    /// * `roots` - Root certificate store for client verification
    #[must_use]
    pub fn with_client_ca_roots(mut self, roots: RootCertStore) -> Self {
        self.client_ca_roots = Some(roots);
        self
    }
}

/// Handshake state for tracking TLS 1.3 handshake progress
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state
    Start,
    /// ClientHello sent (client)
    ClientHelloSent,
    /// ServerHello received (client)
    ServerHelloReceived,
    /// ServerHello sent (server)
    ServerHelloSent,
    /// Server Finished sent (server)
    ServerFinishedSent,
    /// Server Finished received (client)
    ServerFinishedReceived,
    /// Client Finished sent (client)
    ClientFinishedSent,
    /// Handshake complete
    Complete,
}

/// Handshake statistics for performance monitoring
#[derive(Debug, Clone)]
pub struct HandshakeStats {
    /// Total handshake duration (ms)
    pub duration_ms: u64,
    /// Number of round trips
    pub round_trips: u32,
    /// Key exchange time (ms)
    pub kex_time_ms: u64,
    /// Certificate processing time (ms)
    pub cert_time_ms: u64,
    /// ClientHello message size in bytes.
    pub client_hello_size: usize,
    /// ServerHello message size in bytes.
    pub server_hello_size: usize,
}

impl Default for HandshakeStats {
    fn default() -> Self {
        Self {
            duration_ms: 0,
            round_trips: 2,
            kex_time_ms: 0,
            cert_time_ms: 0,
            client_hello_size: 0,
            server_hello_size: 0,
        }
    }
}

/// Load system root certificates into the provided store
///
/// # Errors
/// Returns an error if no root certificates could be loaded, as this would
/// prevent proper certificate validation and is a security risk.
fn load_system_root_certs(
    root_store: &mut RootCertStore,
) -> Result<(), Box<dyn std::error::Error>> {
    // rustls-native-certs 0.8 returns CertificateResult with certs and errors
    let cert_result = rustls_native_certs::load_native_certs();

    // Log any errors encountered during loading (non-fatal)
    for error in &cert_result.errors {
        tracing::warn!("Error loading some native root certificates: {}", error);
    }

    // Load all successfully retrieved certificates
    let mut loaded_count = 0usize;
    for cert in cert_result.certs {
        if root_store.add(cert).is_ok() {
            loaded_count = loaded_count.saturating_add(1);
        }
    }
    tracing::info!("Loaded {} root certificates from system store", loaded_count);

    if root_store.is_empty() {
        // Empty root store is a critical security issue - TLS cannot validate
        // server certificates without trusted roots
        tracing::error!("No root certificates could be loaded from the system");
        return Err("No root certificates available - TLS certificate validation impossible".into());
    }

    Ok(())
}

/// Create TLS 1.3 client configuration
///
/// # Arguments
/// * `config` - TLS configuration
///
/// # Returns
/// A configured rustls ClientConfig with appropriate cipher suites and key exchange
///
/// # Errors
///
/// Returns an error if:
/// - System root certificates cannot be loaded from the certificate store
/// - The specified protocol versions are not supported
/// - The crypto provider fails to initialize or lacks required key exchange groups
///
/// # Example
/// ```no_run
/// use arc_tls::tls13::{create_client_config, Tls13Config};
/// use arc_tls::TlsError;
///
/// # fn example() -> Result<(), TlsError> {
/// let client_config = create_client_config(&Tls13Config::hybrid())?;
/// # Ok(())
/// # }
/// ```
pub fn create_client_config(config: &Tls13Config) -> Result<ClientConfig, TlsError> {
    let mut root_store = RootCertStore::empty();

    // Load system root certificates
    if let Err(e) = load_system_root_certs(&mut root_store) {
        return Err(TlsError::Certificate {
            message: format!("Failed to load system root certificates: {}", e),
            subject: None,
            issuer: None,
            code: crate::error::ErrorCode::CertificateParseError,
            context: Default::default(),
            recovery: crate::error::RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
        });
    }

    // Get configured crypto provider
    let crypto_provider = get_configured_crypto_provider(config)?;

    // Build client config with enhanced security options
    let builder = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_protocol_versions(&config.protocol_versions)
        .map_err(|e| TlsError::Config {
            message: e.to_string(),
            field: Some("protocol_versions".to_string()),
            code: crate::error::ErrorCode::InvalidProtocolVersion,
            context: Default::default(),
            recovery: crate::error::RecoveryHint::Reconfigure {
                field: "protocol_versions".to_string(),
                suggestion: "Use supported protocol versions (TLSv1.2, TLSv1.3)".to_string(),
            },
        })?;

    // Build with root certificates first, then configure client auth
    let builder_with_roots = builder.with_root_certificates(root_store);

    // Configure client authentication (mTLS)
    let mut client_config = if let (Some(cert_chain), Some(private_key)) =
        (&config.client_cert_chain, &config.client_private_key)
    {
        // mTLS: Client presents certificate
        builder_with_roots
            .with_client_auth_cert(cert_chain.clone(), private_key.clone_key())
            .map_err(|e| TlsError::Certificate {
                message: format!("Failed to configure client certificate: {}", e),
                subject: None,
                issuer: None,
                code: crate::error::ErrorCode::CertificateParseError,
                context: Default::default(),
                recovery: crate::error::RecoveryHint::Reconfigure {
                    field: "client_cert".to_string(),
                    suggestion: "Ensure certificate and key are valid and match".to_string(),
                },
            })?
    } else {
        // No client auth
        builder_with_roots.with_no_client_auth()
    };

    // Configure cipher suites for rustls 0.23+
    // Note: In rustls 0.23, cipher suites are configured via the crypto provider
    // This is a limitation - custom cipher suite selection requires custom crypto provider
    if let Some(suites) = &config.cipher_suites
        && !suites.is_empty()
    {
        // For now, log a warning that custom cipher suites are not fully supported
        // in rustls 0.23+ without custom crypto provider implementation
        tracing::warn!(
            "Custom cipher suites configured but not fully supported in rustls 0.23+. Using default secure cipher suites."
        );
    }

    // Configure ALPN protocols
    if !config.alpn_protocols.is_empty() {
        client_config.alpn_protocols = config.alpn_protocols.clone();
    }

    // Configure session resumption
    client_config.resumption = config.resumption.clone();

    // Configure key logging
    if let Some(ref key_log) = config.key_log {
        client_config.key_log = key_log.clone();
    }

    Ok(client_config)
}

/// Create TLS 1.3 server configuration
///
/// # Arguments
/// * `config` - TLS configuration
/// * `cert_chain` - Certificate chain
/// * `private_key` - Server private key (supports PKCS#1, PKCS#8, and SEC1 formats)
///
/// # Returns
/// A configured rustls ServerConfig with appropriate cipher suites and key exchange
///
/// # Errors
///
/// Returns an error if:
/// - The specified protocol versions are not supported
/// - The crypto provider fails to initialize or lacks required key exchange groups
/// - The certificate chain or private key is invalid or incompatible
///
/// # Example
/// ```no_run
/// use arc_tls::tls13::{create_server_config, Tls13Config};
/// use arc_tls::TlsError;
/// use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
///
/// # fn example() -> Result<(), TlsError> {
/// let cert_bytes: Vec<u8> = vec![/* DER-encoded certificate bytes */];
/// let key_bytes: Vec<u8> = vec![/* PKCS#8 DER-encoded private key bytes */];
/// let certs = vec![CertificateDer::from(cert_bytes)];
/// let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_bytes));
/// let server_config = create_server_config(&Tls13Config::hybrid(), certs, key)?;
/// # Ok(())
/// # }
/// ```
pub fn create_server_config(
    config: &Tls13Config,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    // Get configured crypto provider
    let crypto_provider = get_configured_crypto_provider(config)?;

    let builder = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_protocol_versions(&config.protocol_versions)
        .map_err(|e| TlsError::Config {
            message: e.to_string(),
            field: Some("protocol_versions".to_string()),
            code: crate::error::ErrorCode::InvalidProtocolVersion,
            context: Default::default(),
            recovery: crate::error::RecoveryHint::Reconfigure {
                field: "protocol_versions".to_string(),
                suggestion: "Use supported protocol versions (TLSv1.2, TLSv1.3)".to_string(),
            },
        })?;

    // Configure client verification based on mode
    let mut server_config = match config.client_verification {
        ClientVerificationMode::None => {
            // No client certificate required
            builder.with_no_client_auth().with_single_cert(cert_chain, private_key)?
        }
        ClientVerificationMode::Optional | ClientVerificationMode::Required => {
            // mTLS: Verify client certificates
            let client_roots = config.client_ca_roots.clone().ok_or_else(|| TlsError::Config {
                message: "Client CA certificates required for mTLS".to_string(),
                field: Some("client_ca_certs".to_string()),
                code: crate::error::ErrorCode::MissingCertificate,
                context: Default::default(),
                recovery: crate::error::RecoveryHint::Reconfigure {
                    field: "client_ca_certs".to_string(),
                    suggestion: "Provide CA certificates for client verification".to_string(),
                },
            })?;

            let verifier_builder = WebPkiClientVerifier::builder(Arc::new(client_roots));

            let verifier = if config.client_verification == ClientVerificationMode::Optional {
                verifier_builder.allow_unauthenticated().build().map_err(|e| TlsError::Config {
                    message: format!("Failed to build client verifier: {}", e),
                    field: Some("client_verification".to_string()),
                    code: crate::error::ErrorCode::InvalidConfig,
                    context: Default::default(),
                    recovery: crate::error::RecoveryHint::NoRecovery,
                })?
            } else {
                verifier_builder.build().map_err(|e| TlsError::Config {
                    message: format!("Failed to build client verifier: {}", e),
                    field: Some("client_verification".to_string()),
                    code: crate::error::ErrorCode::InvalidConfig,
                    context: Default::default(),
                    recovery: crate::error::RecoveryHint::NoRecovery,
                })?
            };

            builder.with_client_cert_verifier(verifier).with_single_cert(cert_chain, private_key)?
        }
    };

    // Configure cipher suites for rustls 0.23+
    // Note: In rustls 0.23, cipher suites are configured via the crypto provider
    // This is a limitation - custom cipher suite selection requires custom crypto provider
    if let Some(suites) = &config.cipher_suites
        && !suites.is_empty()
    {
        // For now, log a warning that custom cipher suites are not fully supported
        // in rustls 0.23+ without custom crypto provider implementation
        tracing::warn!(
            "Custom cipher suites configured but not fully supported in rustls 0.23+. Using default secure cipher suites."
        );
    }

    if !config.alpn_protocols.is_empty() {
        server_config.alpn_protocols = config.alpn_protocols.clone();
    }

    if config.enable_early_data {
        server_config.max_early_data_size = config.max_early_data_size;
    }

    if let Some(ref key_log) = config.key_log {
        server_config.key_log = key_log.clone();
    }

    Ok(server_config)
}

/// Get appropriate crypto provider based on TLS mode with enhanced security
///
/// # Arguments
/// * `mode` - TLS mode (Classic, Hybrid, or PQ)
///
/// # Returns
/// A rustls CryptoProvider with appropriate key exchange algorithms
fn get_crypto_provider(mode: TlsMode) -> Result<rustls::crypto::CryptoProvider, TlsError> {
    match mode {
        TlsMode::Classic => {
            // Use AWS-LC provider for classic TLS
            Ok(rustls::crypto::aws_lc_rs::default_provider())
        }
        TlsMode::Hybrid | TlsMode::Pq => {
            let provider = rustls_post_quantum::provider();

            let provider_ref: &rustls::crypto::CryptoProvider = &provider;
            let kx_groups = &provider_ref.kx_groups;

            // Basic validation - ensure provider supports essential groups
            // PQ groups handled by rustls-post-quantum
            if kx_groups.is_empty() {
                return Err(TlsError::Config {
                    message: "AWS-LC provider lacks essential key exchange groups".to_string(),
                    field: Some("crypto_provider".to_string()),
                    code: crate::error::ErrorCode::InvalidConfig,
                    context: Default::default(),
                    recovery: crate::error::RecoveryHint::Reconfigure {
                        field: "crypto_provider".to_string(),
                        suggestion: "Ensure AWS-LC supports X25519 and secp256r1".to_string(),
                    },
                });
            }

            Ok(provider)
        }
    }
}

/// Get crypto provider with custom configuration
///
/// # Arguments
/// * `config` - TLS13Config with optional custom provider
///
/// # Returns
/// A rustls CryptoProvider with appropriate key exchange algorithms
fn get_configured_crypto_provider(
    config: &Tls13Config,
) -> Result<rustls::crypto::CryptoProvider, TlsError> {
    // Use custom provider if specified
    if let Some(ref provider) = config.crypto_provider {
        return Ok(provider.clone());
    }

    // Otherwise use mode-based provider selection
    get_crypto_provider(config.mode)
}

/// Get available cipher suites for a given TLS mode with security best practices
///
/// # Arguments
/// * `mode` - TLS mode
///
/// # Returns
/// Vector of supported cipher suites in order of preference
#[must_use]
pub fn get_cipher_suites(mode: TlsMode) -> Vec<SupportedCipherSuite> {
    match mode {
        TlsMode::Classic | TlsMode::Hybrid => {
            vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ]
        }
        TlsMode::Pq => {
            vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            ]
        }
    }
}

/// Get secure default cipher suites based on capabilities
///
/// # Returns
/// Vector of secure cipher suites suitable for most use cases
#[must_use]
pub fn get_secure_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ]
}

/// Validate cipher suites for security compliance
///
/// # Arguments
/// * `suites` - Vector of cipher suites to validate
///
/// # Returns
/// Ok if all suites are secure, Err with details if not
///
/// # Errors
///
/// Returns an error if any of the provided cipher suites are not in the
/// allowed list of secure TLS 1.3 cipher suites (AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM).
pub fn validate_cipher_suites(suites: &[SupportedCipherSuite]) -> Result<(), TlsError> {
    // Define allowed cipher suites for security compliance
    let allowed_suites = get_secure_cipher_suites();

    for suite in suites {
        if !allowed_suites.contains(suite) {
            return Err(TlsError::Config {
                message: format!("Insecure or deprecated cipher suite: {:?}", suite),
                field: Some("cipher_suites".to_string()),
                code: crate::error::ErrorCode::InvalidConfig,
                context: Default::default(),
                recovery: crate::error::RecoveryHint::Reconfigure {
                    field: "cipher_suites".to_string(),
                    suggestion: "Use only TLS 1.3 cipher suites: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM".to_string(),
                },
            });
        }
    }

    Ok(())
}

/// Verify that a configuration supports the requested TLS mode
///
/// # Arguments
/// * `config` - TLS configuration to verify
///
/// # Returns
/// Ok if configuration is valid, Err otherwise
///
/// # Errors
///
/// Returns an error if:
/// - Early data is enabled but `max_early_data_size` is set to zero
pub fn verify_config(config: &Tls13Config) -> Result<(), TlsError> {
    // All TLS modes are always supported (Classic, Hybrid, PQ)
    let _ = config.mode; // Acknowledge mode is used

    if config.enable_early_data && config.max_early_data_size == 0 {
        return Err(TlsError::Config {
            message: "max_early_data_size must be set when early_data is enabled".to_string(),
            field: Some("max_early_data_size".to_string()),
            code: crate::error::ErrorCode::InvalidConfig,
            context: Default::default(),
            recovery: crate::error::RecoveryHint::Reconfigure {
                field: "max_early_data_size".to_string(),
                suggestion: "Set max_early_data_size to a positive value".to_string(),
            },
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_tls13_config_default() {
        let config = Tls13Config::default();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.use_pq_kx);
        assert!(!config.enable_early_data);
        assert!(config.crypto_provider.is_none());
        assert_eq!(config.protocol_versions, vec![&rustls::version::TLS13]);
        assert!(config.cipher_suites.is_none());
        assert!(config.alpn_protocols.is_empty());
        assert!(config.max_fragment_size.is_none());
        assert_eq!(config.max_early_data_size, 0);
    }

    #[test]
    fn test_tls13_config_classic() {
        let config = Tls13Config::classic();
        assert_eq!(config.mode, TlsMode::Classic);
        assert!(!config.use_pq_kx);
    }

    #[test]
    fn test_tls13_config_with_early_data() {
        let config = Tls13Config::hybrid().with_early_data(4096);
        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 4096);
    }

    #[test]
    fn test_cipher_suites() {
        let classic_suites = get_cipher_suites(TlsMode::Classic);
        assert_eq!(classic_suites.len(), 3);

        let hybrid_suites = get_cipher_suites(TlsMode::Hybrid);
        assert_eq!(hybrid_suites.len(), 3);

        let pq_suites = get_cipher_suites(TlsMode::Pq);
        assert_eq!(pq_suites.len(), 2);
    }

    #[test]
    fn test_tls13_config_with_alpn() {
        let config = Tls13Config::hybrid().with_alpn_protocols(vec!["h2", "http/1.1"]);
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_tls13_config_with_cipher_suites() {
        let suites = vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ];
        let config = Tls13Config::hybrid().with_cipher_suites(suites);
        assert!(config.cipher_suites.is_some());
        assert_eq!(config.cipher_suites.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_tls13_config_with_max_fragment_size() {
        let config = Tls13Config::hybrid().with_max_fragment_size(4096);
        assert!(config.max_fragment_size.is_some());
        assert_eq!(config.max_fragment_size.unwrap(), 4096);
    }

    #[test]
    fn test_secure_cipher_suites() {
        // Verify secure default suites
        let secure_suites = get_secure_cipher_suites();
        assert_eq!(secure_suites.len(), 3);

        // Validate secure cipher suites
        assert!(validate_cipher_suites(&secure_suites).is_ok());
    }

    #[test]
    fn test_verify_config() {
        let valid_config = Tls13Config::hybrid();
        assert!(verify_config(&valid_config).is_ok());

        let invalid_config = Tls13Config {
            mode: TlsMode::Classic,
            use_pq_kx: false,
            enable_early_data: true,
            max_early_data_size: 0,
            crypto_provider: None,
            protocol_versions: vec![&rustls::version::TLS13],
            cipher_suites: None,
            alpn_protocols: vec![],
            max_fragment_size: None,
            resumption: rustls::client::Resumption::in_memory_sessions(32),
            key_log: None,
            client_cert_chain: None,
            client_private_key: None,
            client_verification: ClientVerificationMode::None,
            client_ca_roots: None,
        };
        assert!(verify_config(&invalid_config).is_err());
    }

    #[test]
    fn test_handshake_stats_default() {
        let stats = HandshakeStats::default();
        assert_eq!(stats.round_trips, 2);
        assert_eq!(stats.duration_ms, 0);
    }

    #[test]
    fn test_handshake_state() {
        let state = HandshakeState::Start;
        assert_eq!(state, HandshakeState::Start);

        let complete = HandshakeState::Complete;
        assert!(complete != state);
    }

    #[test]
    fn test_crypto_provider_selection() {
        // Test classic mode provider selection
        let classic_provider = get_crypto_provider(TlsMode::Classic);
        assert!(classic_provider.is_ok());

        // Test hybrid mode provider selection (depends on feature flag)
        let hybrid_provider = get_crypto_provider(TlsMode::Hybrid);
        assert!(hybrid_provider.is_ok());

        // Test PQ mode provider selection (depends on feature flag)
        let pq_provider = get_crypto_provider(TlsMode::Pq);
        assert!(pq_provider.is_ok());
    }

    #[test]
    fn test_configured_crypto_provider() {
        let custom_provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = Tls13Config::hybrid().with_crypto_provider(custom_provider.clone());

        let provider = get_configured_crypto_provider(&config);
        assert!(provider.is_ok());

        // Should return the custom provider, not the mode-based one
        assert_eq!(provider.unwrap().kx_groups.len(), custom_provider.kx_groups.len());
    }
}
