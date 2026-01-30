#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # LatticeArc TLS
//!
//! TLS 1.3 implementation with post-quantum key exchange support.
//!
//! This crate provides TLS connectivity with hybrid key exchange (ECDHE + ML-KEM)
//! for quantum-resistant secure communications.
//!
//! ## Features
//!
//! - **Hybrid Key Exchange**: X25519MLKEM768 (ECDHE + ML-KEM) for post-quantum security
//! - **Backward Compatible**: Works with standard TLS 1.3 clients
//! - **Flexible Modes**: Classic, Hybrid, and PQ-only modes
//! - **Easy API**: Simple client/server connector functions
//! - **Comprehensive Error Handling**: Detailed error types, recovery mechanisms, and tracing
//!
//! ## Quick Start
//!
//! ```no_run
//! use arc_tls::*;
//!
//! # async fn example() -> Result<(), TlsError> {
//! // Client connection (default: hybrid mode)
//! let stream = tls_connect("example.com:443", "example.com", &TlsConfig::default()).await?;
//!
//! // Server setup
//! let acceptor = create_server_acceptor(&TlsConfig::default(), "server.crt", "server.key")?;
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await.map_err(TlsError::from)?;
//! let (tcp_stream, _) = listener.accept().await.map_err(TlsError::from)?;
//! let tls_stream = tls_accept(tcp_stream, &acceptor).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! The crate provides comprehensive error handling with:
//! - Detailed error types with error codes
//! - Error recovery mechanisms (retry, fallback, circuit breaker)
//! - Structured logging with tracing
//! - Error context propagation
//!
//! ```no_run
//! use arc_tls::*;
//! use arc_tls::recovery::{RetryPolicy, retry_with_policy};
//!
//! # async fn example() -> Result<(), TlsError> {
//! let policy = RetryPolicy::default();
//! let result = retry_with_policy(&policy, || async {
//!     tls_connect("example.com:443", "example.com", &TlsConfig::default()).await
//! }, "TLS connection").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## TLS Modes
//!
//! ### Hybrid Mode (Default, Recommended)
//! Uses X25519MLKEM768 combining:
//! - X25519: Classical ECDH, well-tested
//! - ML-KEM-768: Post-quantum KEM (NIST FIPS 203)
//!
//! Security: Requires breaking BOTH components
//!
//! ### Classic Mode
//! Standard TLS 1.3 with X25519 only. Not PQ secure.
//!
//! ### PQ-Only Mode
//! Post-quantum only with ML-KEM. May have compatibility issues.
//!
//!
//! ## Performance Impact
//!
//! Hybrid TLS 1.3 with X25519MLKEM768:
//! - ClientHello: +1184 bytes (ML-KEM key share)
//! - ServerHello: +1088 bytes (ML-KEM ciphertext)
//! - CPU overhead: ~2-3x on key exchange (negligible overall)
//!
//! See [rustls performance report](https://rustls.dev/perf/2024-12-17-pq-kx/) for details.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         TLS 1.3 Handshake                           │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Client                                              Server         │
//! │    │                                                   │            │
//! │    │  ClientHello                                      │            │
//! │    │  ├─ supported_versions: TLS 1.3                   │            │
//! │    │  ├─ key_share: X25519 (32 bytes)                  │            │
//! │    │  └─ key_share: ML-KEM-768 (1184 bytes) ◄── PQ     │            │
//! │    │──────────────────────────────────────────────────►│            │
//! │    │                                                   │            │
//! │    │                               ServerHello         │            │
//! │    │               key_share: X25519 (32 bytes) ──┤    │            │
//! │    │  key_share: ML-KEM-768 ciphertext (1088 bytes) ◄──┤            │
//! │    │◄──────────────────────────────────────────────────│            │
//! │    │                                                   │            │
//! │    │        ┌────────────────────────────────┐         │            │
//! │    │        │  Hybrid Shared Secret (64 B)   │         │            │
//! │    │        │  = HKDF(X25519_SS ║ ML-KEM_SS) │         │            │
//! │    │        └────────────────────────────────┘         │            │
//! │    │                                                   │            │
//! │    │  {EncryptedExtensions}                            │            │
//! │    │  {Certificate}                                    │            │
//! │    │  {CertificateVerify}                              │            │
//! │    │  {Finished}                                       │            │
//! │    │◄──────────────────────────────────────────────────│            │
//! │    │                                                   │            │
//! │    │  {Finished}                                       │            │
//! │    │──────────────────────────────────────────────────►│            │
//! │    │                                                   │            │
//! │    │◄═════════════════════════════════════════════════►│            │
//! │    │            Application Data (encrypted)           │            │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//! Security: Attacker must break BOTH X25519 AND ML-KEM to compromise session
//! ```

pub mod basic_features;
pub mod context;
pub mod error;
pub mod pq_key_exchange;
pub mod recovery;
pub mod selector;
pub mod session_store;
pub mod tls13;
pub mod tracing;

pub use basic_features::{
    create_client_connector, create_server_acceptor, get_config_info, load_certs, load_private_key,
    tls_accept, tls_connect,
};
pub use context::{
    DiagnosticInfo, ErrorChain, ErrorLink, SystemInfo, TlsContext as TlsDiagnosticContext,
};
pub use error::{ErrorCode, ErrorContext, ErrorSeverity, OperationPhase, RecoveryHint, TlsError};
pub use pq_key_exchange::{
    KexInfo, PqKexMode, get_kex_info, get_kex_provider, is_custom_hybrid_available, is_pq_available,
};
pub use recovery::{
    CircuitBreaker, DegradationConfig, FallbackStrategy, RetryPolicy, execute_with_circuit_breaker,
    execute_with_fallback, retry_with_policy,
};
pub use selector::{
    CLASSICAL_TLS_KEX, CLASSICAL_TLS_SCHEME, DEFAULT_PQ_TLS_KEX, DEFAULT_PQ_TLS_SCHEME,
    DEFAULT_TLS_KEX, DEFAULT_TLS_SCHEME, HYBRID_TLS_512, HYBRID_TLS_768, HYBRID_TLS_1024,
    PQ_TLS_512, PQ_TLS_768, PQ_TLS_1024, TlsConstraints, TlsContext, TlsPolicyEngine, TlsUseCase,
};
pub use session_store::{
    ConfigurableSessionStore, PersistentSessionStore, create_resumption_config,
    create_session_store,
};
pub use tls13::{
    HandshakeState, HandshakeStats, Tls13Config, create_client_config, create_server_config,
    get_cipher_suites, verify_config,
};
pub use tracing::{TlsMetrics, TlsSpan, TracingConfig, init_tracing};

/// TLS configuration modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// Classic TLS 1.3 with ECDHE only (not PQ secure)
    Classic,
    /// Hybrid TLS 1.3 with ECDHE + ML-KEM (default, PQ secure)
    #[default]
    Hybrid,
    /// Post-quantum only TLS 1.3 with ML-KEM (PQ secure)
    Pq,
}

/// Client authentication configuration for mTLS
#[derive(Debug, Clone)]
pub struct ClientAuthConfig {
    /// Path to client certificate file (PEM format)
    pub cert_path: String,
    /// Path to client private key file (PEM format)
    pub key_path: String,
}

impl ClientAuthConfig {
    /// Create a new client authentication configuration
    ///
    /// # Arguments
    /// * `cert_path` - Path to client certificate file (PEM format)
    /// * `key_path` - Path to client private key file (PEM format)
    #[must_use]
    pub fn new(cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        Self { cert_path: cert_path.into(), key_path: key_path.into() }
    }
}

/// Server-side client verification mode for mTLS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientVerificationMode {
    /// No client certificate required (default)
    #[default]
    None,
    /// Client certificate optional - verify if provided
    Optional,
    /// Client certificate required - reject if not provided
    Required,
}

/// Session persistence configuration
#[derive(Debug, Clone)]
pub struct SessionPersistenceConfig {
    /// Path to session cache file
    pub path: std::path::PathBuf,
    /// Maximum number of sessions to cache
    pub max_sessions: usize,
}

impl SessionPersistenceConfig {
    /// Create a new session persistence configuration
    ///
    /// # Arguments
    /// * `path` - Path to session cache file
    /// * `max_sessions` - Maximum number of sessions to cache
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>, max_sessions: usize) -> Self {
        Self { path: path.into(), max_sessions }
    }
}

/// TLS configuration with comprehensive security options
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// TLS mode (Classic, Hybrid, or PQ)
    pub mode: TlsMode,
    /// Enable tracing for this connection
    pub enable_tracing: bool,
    /// Retry policy for automatic retries
    pub retry_policy: Option<RetryPolicy>,
    /// Enable fallback strategies
    pub enable_fallback: bool,
    /// ALPN protocols to negotiate (e.g., "h2", "http/1.1")
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Maximum fragment size for TLS records (None for default 16KB)
    pub max_fragment_size: Option<usize>,
    /// Enable early data (0-RTT) support
    pub enable_early_data: bool,
    /// Maximum early data size in bytes
    pub max_early_data_size: u32,
    /// Require Secure Renegotiation
    pub require_secure_renegotiation: bool,
    /// Enable TLS session resumption
    pub enable_resumption: bool,
    /// Session ticket lifetime in seconds
    pub session_lifetime: u32,
    /// Enable logging of key material for debugging (DANGEROUS - only for testing)
    pub enable_key_logging: bool,
    /// Custom cipher suite preference (None for secure defaults)
    pub cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
    /// Minimum protocol version (TLS 1.2 or TLS 1.3 recommended)
    pub min_protocol_version: Option<rustls::ProtocolVersion>,
    /// Maximum protocol version
    pub max_protocol_version: Option<rustls::ProtocolVersion>,
    /// Client authentication configuration for mTLS (client-side)
    pub client_auth: Option<ClientAuthConfig>,
    /// Server-side client verification mode for mTLS
    pub client_verification: ClientVerificationMode,
    /// Path to CA certificates for client verification (server-side mTLS)
    pub client_ca_certs: Option<String>,
    /// Session persistence configuration (None for in-memory only)
    pub session_persistence: Option<SessionPersistenceConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            enable_tracing: false,
            retry_policy: None,
            enable_fallback: true,
            alpn_protocols: vec![],
            max_fragment_size: None,
            enable_early_data: false,
            max_early_data_size: 0,
            require_secure_renegotiation: true,
            enable_resumption: true,
            session_lifetime: 7200, // 2 hours default
            enable_key_logging: false,
            cipher_suites: None,
            min_protocol_version: Some(rustls::ProtocolVersion::TLSv1_3),
            max_protocol_version: Some(rustls::ProtocolVersion::TLSv1_3),
            client_auth: None,
            client_verification: ClientVerificationMode::default(),
            client_ca_certs: None,
            session_persistence: None,
        }
    }
}

impl TlsConfig {
    /// Create a new TLS configuration with defaults (Hybrid mode, High security).
    ///
    /// This is the starting point for the builder pattern. Use `.use_case()` or
    /// `.security_level()` to configure algorithm selection.
    ///
    /// # Example
    /// ```
    /// use arc_tls::TlsConfig;
    ///
    /// // Simple: Use defaults (Hybrid mode)
    /// let config = TlsConfig::new();
    ///
    /// // With use case (recommended)
    /// let config = TlsConfig::new()
    ///     .use_case(arc_tls::TlsUseCase::FinancialServices);
    ///
    /// // With security level
    /// let config = TlsConfig::new()
    ///     .security_level(arc_core::SecurityLevel::Maximum);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the use case for automatic TLS mode selection (recommended).
    ///
    /// The library will choose the optimal TLS mode for this use case.
    /// This is the recommended way to configure TLS.
    ///
    /// # Use Case → Mode Mapping
    ///
    /// | Use Case | Mode | Rationale |
    /// |----------|------|-----------|
    /// | `WebServer` | Hybrid | Balance security + compatibility |
    /// | `FinancialServices` | Hybrid | Compliance + PQ protection |
    /// | `Government` | PQ | Maximum quantum resistance |
    /// | `IoT` | Classic | Resource constraints |
    ///
    /// # Example
    /// ```
    /// use arc_tls::{TlsConfig, TlsUseCase};
    ///
    /// let config = TlsConfig::new()
    ///     .use_case(TlsUseCase::FinancialServices)
    ///     .with_tracing();
    /// ```
    #[must_use]
    pub fn use_case(mut self, use_case: TlsUseCase) -> Self {
        self.mode = TlsPolicyEngine::recommend_mode(use_case);
        self
    }

    /// Set the security level for TLS mode selection.
    ///
    /// Maps security levels to appropriate TLS modes:
    /// - `Maximum` → PQ (full quantum resistance)
    /// - `High` → Hybrid (quantum + classical)
    /// - `Medium` → Hybrid (quantum + classical)
    /// - `Low` → Classic (classical only)
    ///
    /// # Example
    /// ```
    /// use arc_tls::TlsConfig;
    /// use arc_core::SecurityLevel;
    ///
    /// let config = TlsConfig::new()
    ///     .security_level(SecurityLevel::Maximum)
    ///     .with_tracing();
    /// ```
    #[must_use]
    pub fn security_level(mut self, level: arc_core::SecurityLevel) -> Self {
        self.mode = TlsPolicyEngine::select_by_security_level(level);
        self
    }

    /// Enable tracing for this configuration
    #[must_use]
    pub fn with_tracing(mut self) -> Self {
        self.enable_tracing = true;
        self
    }

    /// Set retry policy for automatic retries
    #[must_use]
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Enable or disable fallback strategies
    #[must_use]
    pub fn with_fallback(mut self, enable: bool) -> Self {
        self.enable_fallback = enable;
        self
    }

    /// Set ALPN protocols for negotiation
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<&'static str>) -> Self {
        self.alpn_protocols = protocols.into_iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    /// Set maximum fragment size for TLS records
    #[must_use]
    pub fn with_max_fragment_size(mut self, size: usize) -> Self {
        self.max_fragment_size = Some(size);
        self
    }

    /// Enable early data (0-RTT) with specified maximum size
    #[must_use]
    pub fn with_early_data(mut self, max_size: u32) -> Self {
        self.enable_early_data = true;
        self.max_early_data_size = max_size;
        self
    }

    /// Set session lifetime in seconds
    #[must_use]
    pub fn with_session_lifetime(mut self, seconds: u32) -> Self {
        self.session_lifetime = seconds;
        self
    }

    /// Enable or disable secure renegotiation requirement
    #[must_use]
    pub fn with_secure_renegotiation(mut self, require: bool) -> Self {
        self.require_secure_renegotiation = require;
        self
    }

    /// Enable or disable session resumption
    #[must_use]
    pub fn with_resumption(mut self, enable: bool) -> Self {
        self.enable_resumption = enable;
        self
    }

    /// Enable key logging (DANGEROUS - only for testing)
    #[must_use]
    pub fn with_key_logging(mut self) -> Self {
        self.enable_key_logging = true;
        self
    }

    /// Set custom cipher suites
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Set minimum protocol version
    #[must_use]
    pub fn with_min_protocol_version(mut self, version: rustls::ProtocolVersion) -> Self {
        self.min_protocol_version = Some(version);
        self
    }

    /// Set maximum protocol version
    #[must_use]
    pub fn with_max_protocol_version(mut self, version: rustls::ProtocolVersion) -> Self {
        self.max_protocol_version = Some(version);
        self
    }

    /// Enable mutual TLS (mTLS) with client certificate authentication
    ///
    /// This configures the client to present a certificate during the TLS handshake.
    /// Use this when connecting to servers that require client authentication.
    ///
    /// # Arguments
    /// * `cert_path` - Path to client certificate file (PEM format)
    /// * `key_path` - Path to client private key file (PEM format)
    ///
    /// # Example
    /// ```
    /// use arc_tls::TlsConfig;
    ///
    /// let config = TlsConfig::new()
    ///     .with_client_auth("client.crt", "client.key");
    /// ```
    #[must_use]
    pub fn with_client_auth(
        mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.client_auth = Some(ClientAuthConfig::new(cert_path, key_path));
        self
    }

    /// Set server-side client verification mode for mTLS
    ///
    /// This configures how the server handles client certificates.
    ///
    /// # Arguments
    /// * `mode` - Client verification mode (None, Optional, or Required)
    ///
    /// # Example
    /// ```
    /// use arc_tls::{TlsConfig, ClientVerificationMode};
    ///
    /// // Require all clients to present valid certificates
    /// let config = TlsConfig::new()
    ///     .with_client_verification(ClientVerificationMode::Required);
    /// ```
    #[must_use]
    pub fn with_client_verification(mut self, mode: ClientVerificationMode) -> Self {
        self.client_verification = mode;
        self
    }

    /// Set CA certificates for client verification (server-side mTLS)
    ///
    /// This configures which CA certificates are trusted for verifying client certificates.
    ///
    /// # Arguments
    /// * `ca_certs_path` - Path to CA certificate file (PEM format)
    ///
    /// # Example
    /// ```
    /// use arc_tls::{TlsConfig, ClientVerificationMode};
    ///
    /// let config = TlsConfig::new()
    ///     .with_client_verification(ClientVerificationMode::Required)
    ///     .with_client_ca_certs("ca-bundle.crt");
    /// ```
    #[must_use]
    pub fn with_client_ca_certs(mut self, ca_certs_path: impl Into<String>) -> Self {
        self.client_ca_certs = Some(ca_certs_path.into());
        self
    }

    /// Enable session persistence for faster reconnections
    ///
    /// Sessions are cached to disk, allowing them to be reused across process restarts.
    /// This significantly reduces handshake latency for repeated connections.
    ///
    /// # Arguments
    /// * `path` - Path to session cache file
    /// * `max_sessions` - Maximum number of sessions to cache
    ///
    /// # Example
    /// ```
    /// use arc_tls::TlsConfig;
    ///
    /// let config = TlsConfig::new()
    ///     .with_session_persistence("/var/cache/tls_sessions.bin", 1000);
    /// ```
    #[must_use]
    pub fn with_session_persistence(
        mut self,
        path: impl Into<std::path::PathBuf>,
        max_sessions: usize,
    ) -> Self {
        self.session_persistence = Some(SessionPersistenceConfig::new(path, max_sessions));
        self
    }

    /// Validate the TLS configuration
    ///
    /// Checks for configuration errors that would cause unexpected behavior
    /// at runtime. Call this after building a configuration to catch issues early.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Config`] if:
    /// - Protocol version range produces no valid versions (e.g., min > max)
    /// - Protocol version range excludes all supported versions
    ///
    /// # Example
    /// ```
    /// use arc_tls::{TlsConfig, TlsError};
    ///
    /// let config = TlsConfig::new()
    ///     .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_2)
    ///     .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
    ///
    /// if let Err(e) = config.validate() {
    ///     eprintln!("Invalid config: {}", e);
    /// }
    /// ```
    pub fn validate(&self) -> Result<(), TlsError> {
        // Validate protocol version range
        if let Some(min_version) = self.min_protocol_version {
            let versions: Vec<&'static rustls::SupportedProtocolVersion> =
                if let Some(max_version) = self.max_protocol_version {
                    rustls::ALL_VERSIONS
                        .iter()
                        .filter(|v| {
                            let v_num: u16 = v.version.into();
                            let min_num: u16 = min_version.into();
                            let max_num: u16 = max_version.into();
                            v_num >= min_num && v_num <= max_num
                        })
                        .copied()
                        .collect()
                } else {
                    rustls::ALL_VERSIONS
                        .iter()
                        .filter(|v| {
                            let v_num: u16 = v.version.into();
                            let min_num: u16 = min_version.into();
                            v_num >= min_num
                        })
                        .copied()
                        .collect()
                };

            if versions.is_empty() {
                return Err(TlsError::Config {
                    message: format!(
                        "Protocol version range ({:?} - {:?}) produces no valid versions. \
                         Supported versions are TLS 1.2 and TLS 1.3.",
                        min_version, self.max_protocol_version
                    ),
                    field: Some("protocol_version".to_string()),
                    code: ErrorCode::InvalidProtocolVersion,
                    context: ErrorContext {
                        code: ErrorCode::InvalidProtocolVersion,
                        phase: OperationPhase::Initialization,
                        ..Default::default()
                    },
                    recovery: RecoveryHint::Reconfigure {
                        field: "min_protocol_version / max_protocol_version".to_string(),
                        suggestion: "Use TLSv1_2 or TLSv1_3 as version bounds".to_string(),
                    },
                });
            }
        }

        Ok(())
    }
}

impl From<&TlsConfig> for Tls13Config {
    fn from(config: &TlsConfig) -> Self {
        let mut tls13_config = match config.mode {
            TlsMode::Classic => Tls13Config::classic(),
            TlsMode::Hybrid => Tls13Config::hybrid(),
            TlsMode::Pq => Tls13Config::pq(),
        };

        // Apply additional configuration from TlsConfig
        if !config.alpn_protocols.is_empty() {
            tls13_config.alpn_protocols = config.alpn_protocols.clone();
        }

        if let Some(size) = config.max_fragment_size {
            tls13_config.max_fragment_size = Some(size);
        }

        if config.enable_early_data {
            tls13_config.enable_early_data = true;
            tls13_config.max_early_data_size = config.max_early_data_size;
        }

        if let Some(min_version) = config.min_protocol_version {
            let versions: Vec<&'static rustls::SupportedProtocolVersion> =
                if let Some(max_version) = config.max_protocol_version {
                    rustls::ALL_VERSIONS
                        .iter()
                        .filter(|v| {
                            let v_num: u16 = v.version.into();
                            let min_num: u16 = min_version.into();
                            let max_num: u16 = max_version.into();
                            v_num >= min_num && v_num <= max_num
                        })
                        .copied()
                        .collect()
                } else {
                    rustls::ALL_VERSIONS
                        .iter()
                        .filter(|v| {
                            let v_num: u16 = v.version.into();
                            let min_num: u16 = min_version.into();
                            v_num >= min_num
                        })
                        .copied()
                        .collect()
                };

            if versions.is_empty() {
                // Log warning: requested protocol versions resulted in empty list
                // This happens when min/max versions don't overlap with supported versions
                // Defaulting to TLS 1.3 since this library is TLS 1.3 focused
                ::tracing::warn!(
                    min_version = ?min_version,
                    max_version = ?config.max_protocol_version,
                    "Requested protocol version range produced empty list. \
                     Defaulting to TLS 1.3. Consider using TLS 1.2 or TLS 1.3."
                );
                tls13_config.protocol_versions = vec![&rustls::version::TLS13];
            } else {
                tls13_config.protocol_versions = versions;
            }
        }

        // Configure cipher suites if specified
        if let Some(ref cipher_suites) = config.cipher_suites {
            tls13_config.cipher_suites = Some(cipher_suites.clone());
        }

        // Configure key logging if enabled
        if config.enable_key_logging {
            tls13_config.key_log = Some(std::sync::Arc::new(rustls::KeyLogFile::new()));
        }

        // Configure mTLS client authentication
        tls13_config.client_verification = config.client_verification;

        tls13_config
    }
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if post-quantum support is enabled
///
/// # Returns
/// Always returns true (PQ support is always enabled)
#[must_use]
pub const fn pq_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_mode_default() {
        assert_eq!(TlsMode::default(), TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_new() {
        let config = TlsConfig::new();
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

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
        use arc_core::SecurityLevel;

        // Maximum uses Hybrid for defense-in-depth
        let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_with_security_level_quantum() {
        use arc_core::SecurityLevel;

        // Quantum is PQ-only (no classical key exchange)
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls_config_with_security_level_standard() {
        use arc_core::SecurityLevel;

        // Standard uses Hybrid
        let config = TlsConfig::new().security_level(SecurityLevel::Standard);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_with_tracing() {
        let config = TlsConfig::new().with_tracing();
        assert!(config.enable_tracing);
    }

    #[test]
    fn test_tls_config_with_retry() {
        let policy = RetryPolicy::default();
        let config = TlsConfig::new().with_retry_policy(policy);
        assert!(config.retry_policy.is_some());
    }

    #[test]
    fn test_tls_config_with_fallback() {
        let config = TlsConfig::new().with_fallback(false);
        assert!(!config.enable_fallback);
    }

    #[test]
    fn test_tls_config_builder_chain() {
        let config = TlsConfig::new()
            .use_case(TlsUseCase::FinancialServices)
            .with_tracing()
            .with_fallback(true);

        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.enable_tracing);
        assert!(config.enable_fallback);
    }

    #[test]
    fn test_tls13_config_from_tls_config() {
        let tls_config = TlsConfig::new();
        let tls13_config = Tls13Config::from(&tls_config);
        assert_eq!(tls13_config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_pq_enabled() {
        // PQ is always enabled
        assert!(pq_enabled());
    }
}
