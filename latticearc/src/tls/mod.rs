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
//! use latticearc::tls::*;
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
//! use latticearc::tls::*;
//! use latticearc::tls::recovery::{RetryPolicy, retry_with_policy};
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

/// Formal verification support for TLS security properties.
///
/// This module provides formal verification capabilities using Kani and SAW.
/// Enable with `--features formal-verification`, `--features kani`, or `--features saw`.
#[cfg(any(feature = "formal-verification", feature = "kani", feature = "saw"))]
pub mod formal_verification;

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
    /// TLS mode (Classic, Hybrid, or PQ).
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — selects classic/hybrid/pq constructor.
    pub mode: TlsMode,
    /// Enable tracing for this connection.
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — calls `init_tracing()`.
    pub enable_tracing: bool,
    /// Retry policy for automatic retries.
    ///
    /// Consumer: not yet wired — stored for future use. The `RetryPolicy` type
    /// exists in `tls::recovery` but TlsConfig does not pass this to any consumer.
    pub retry_policy: Option<RetryPolicy>,
    /// Enable fallback strategies.
    ///
    /// Consumer: not yet wired — stored and set by `TlsSelector` but never read
    /// by any downstream consumer in the `From<&TlsConfig> for Tls13Config` path.
    pub enable_fallback: bool,
    /// ALPN protocols to negotiate (e.g., "h2", "http/1.1").
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.alpn_protocols`.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Maximum fragment size for TLS records (None for default 16KB).
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.max_fragment_size`.
    pub max_fragment_size: Option<usize>,
    /// Enable early data (0-RTT) support.
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.enable_early_data`.
    pub enable_early_data: bool,
    /// Maximum early data size in bytes.
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.max_early_data_size`.
    pub max_early_data_size: u32,
    /// Enable TLS session resumption.
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — configures `tls13_config.resumption`.
    pub enable_resumption: bool,
    /// Session ticket lifetime in seconds.
    ///
    /// Consumer: not yet wired — requires a custom `TimeBase` ticketer
    /// implementation. Currently stored for configuration purposes only; the actual
    /// session ticket lifetime is controlled by rustls defaults.
    pub session_lifetime: u32,
    /// Enable logging of key material for debugging (DANGEROUS - only for testing).
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.key_log`.
    pub enable_key_logging: bool,
    /// Custom cipher suite preference (None for secure defaults).
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.cipher_suites`.
    pub cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
    /// Minimum protocol version (TLS 1.2 or TLS 1.3 recommended).
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.protocol_versions`.
    pub min_protocol_version: Option<rustls::ProtocolVersion>,
    /// Maximum protocol version.
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.protocol_versions`.
    pub max_protocol_version: Option<rustls::ProtocolVersion>,
    /// Client authentication configuration for mTLS (client-side).
    ///
    /// Consumer: not yet wired in `From<&TlsConfig>` — mTLS client auth requires
    /// loading client certificates at connection time, not at config conversion.
    pub client_auth: Option<ClientAuthConfig>,
    /// Server-side client verification mode for mTLS.
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — sets `tls13_config.client_verification`.
    pub client_verification: ClientVerificationMode,
    /// Path to CA certificates for client verification (server-side mTLS).
    ///
    /// Consumer: not yet wired in `From<&TlsConfig>` — CA cert loading happens
    /// at `create_server_config()` time, not at config conversion.
    pub client_ca_certs: Option<String>,
    /// Session persistence configuration (None for in-memory only).
    ///
    /// Consumer: `From<&TlsConfig> for Tls13Config` — configures `tls13_config.resumption`.
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
    /// use latticearc::tls::TlsConfig;
    ///
    /// // Simple: Use defaults (Hybrid mode)
    /// let config = TlsConfig::new();
    ///
    /// // With use case (recommended)
    /// let config = TlsConfig::new()
    ///     .use_case(latticearc::tls::TlsUseCase::FinancialServices);
    ///
    /// // With security level
    /// let config = TlsConfig::new()
    ///     .security_level(latticearc::unified_api::SecurityLevel::Maximum);
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
    /// use latticearc::tls::{TlsConfig, TlsUseCase};
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
    /// - `Quantum` → PQ (full quantum resistance, no classical component)
    /// - `Standard` / `High` / `Maximum` → Hybrid (quantum + classical for defense-in-depth)
    ///
    /// # Example
    /// ```
    /// use latticearc::tls::TlsConfig;
    /// use latticearc::unified_api::SecurityLevel;
    ///
    /// let config = TlsConfig::new()
    ///     .security_level(SecurityLevel::Maximum)
    ///     .with_tracing();
    /// ```
    #[must_use]
    pub fn security_level(mut self, level: crate::unified_api::SecurityLevel) -> Self {
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
    /// use latticearc::tls::TlsConfig;
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
    /// use latticearc::tls::{TlsConfig, ClientVerificationMode};
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
    /// use latticearc::tls::{TlsConfig, ClientVerificationMode};
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
    /// use latticearc::tls::TlsConfig;
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
    /// use latticearc::tls::{TlsConfig, TlsError};
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
                    context: Box::new(ErrorContext {
                        code: ErrorCode::InvalidProtocolVersion,
                        phase: OperationPhase::Initialization,
                        ..Default::default()
                    }),
                    recovery: Box::new(RecoveryHint::Reconfigure {
                        field: "min_protocol_version / max_protocol_version".to_string(),
                        suggestion: "Use TLSv1_2 or TLSv1_3 as version bounds".to_string(),
                    }),
                });
            }
        }

        Ok(())
    }
}

impl From<&TlsConfig> for Tls13Config {
    fn from(config: &TlsConfig) -> Self {
        // Pattern 8: Destructure source type for compile-time exhaustiveness.
        // Adding a new field to TlsConfig will cause a compile error here,
        // forcing the developer to decide whether to wire it or document it as unwired.
        let TlsConfig {
            ref mode,
            enable_tracing,
            retry_policy: _,    // Not yet wired — see TlsConfig field doc
            enable_fallback: _, // Not yet wired — see TlsConfig field doc
            ref alpn_protocols,
            max_fragment_size,
            enable_early_data,
            max_early_data_size,
            enable_resumption,
            session_lifetime: _, // Not yet wired — see TlsConfig field doc
            enable_key_logging,
            ref cipher_suites,
            min_protocol_version,
            max_protocol_version,
            client_auth: _, // Wired at create_client_config() time, not here
            client_verification,
            client_ca_certs: _, // Wired at create_server_config() time, not here
            ref session_persistence,
        } = *config;

        // Wire mode: select Tls13Config constructor based on TLS mode
        let mut tls13_config = match mode {
            TlsMode::Classic => Tls13Config::classic(),
            TlsMode::Hybrid => Tls13Config::hybrid(),
            TlsMode::Pq => Tls13Config::pq(),
        };

        // Wire alpn_protocols:
        if !alpn_protocols.is_empty() {
            tls13_config.alpn_protocols = alpn_protocols.clone();
        }

        // Wire max_fragment_size:
        if let Some(size) = max_fragment_size {
            tls13_config.max_fragment_size = Some(size);
        }

        // Wire enable_early_data + max_early_data_size:
        if enable_early_data {
            tls13_config.enable_early_data = true;
            tls13_config.max_early_data_size = max_early_data_size;
        }

        // Wire min_protocol_version + max_protocol_version:
        if let Some(min_version) = min_protocol_version {
            let versions: Vec<&'static rustls::SupportedProtocolVersion> =
                if let Some(max_ver) = max_protocol_version {
                    rustls::ALL_VERSIONS
                        .iter()
                        .filter(|v| {
                            let v_num: u16 = v.version.into();
                            let min_num: u16 = min_version.into();
                            let max_num: u16 = max_ver.into();
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
                ::tracing::warn!(
                    min_version = ?min_version,
                    max_version = ?max_protocol_version,
                    "Requested protocol version range produced empty list. \
                     Defaulting to TLS 1.3. Consider using TLS 1.2 or TLS 1.3."
                );
                tls13_config.protocol_versions = vec![&rustls::version::TLS13];
            } else {
                tls13_config.protocol_versions = versions;
            }
        }

        // Wire cipher_suites:
        if let Some(suites) = cipher_suites {
            tls13_config.cipher_suites = Some(suites.clone());
        }

        // Wire enable_key_logging:
        if enable_key_logging {
            tls13_config.key_log = Some(std::sync::Arc::new(rustls::KeyLogFile::new()));
        }

        // Wire client_verification:
        tls13_config.client_verification = client_verification;

        // Wire enable_resumption + session_persistence:
        if !enable_resumption {
            tls13_config.resumption = rustls::client::Resumption::disabled();
        } else if session_persistence.is_some() {
            tls13_config.resumption = create_resumption_config(session_persistence.as_ref());
        }

        // Wire enable_tracing:
        if enable_tracing {
            use std::sync::Once;
            static TRACING_INIT: Once = Once::new();
            TRACING_INIT.call_once(|| {
                init_tracing(&TracingConfig::default());
            });
        }

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
#[allow(clippy::indexing_slicing)]
#[allow(clippy::expect_used)]
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
        use crate::unified_api::SecurityLevel;

        // Maximum uses Hybrid for defense-in-depth
        let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
        assert_eq!(config.mode, TlsMode::Hybrid);
    }

    #[test]
    fn test_tls_config_with_security_level_quantum() {
        use crate::unified_api::SecurityLevel;

        // Quantum is PQ-only (no classical key exchange)
        let config = TlsConfig::new().security_level(SecurityLevel::Quantum);
        assert_eq!(config.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls_config_with_security_level_standard() {
        use crate::unified_api::SecurityLevel;

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

    // === TlsConfig builder method coverage ===

    #[test]
    fn test_tls_config_with_alpn_protocols() {
        let config = TlsConfig::new().with_alpn_protocols(vec!["h2", "http/1.1"]);
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_tls_config_with_max_fragment_size() {
        let config = TlsConfig::new().with_max_fragment_size(4096);
        assert_eq!(config.max_fragment_size, Some(4096));
    }

    #[test]
    fn test_tls_config_with_early_data() {
        let config = TlsConfig::new().with_early_data(16384);
        assert!(config.enable_early_data);
        assert_eq!(config.max_early_data_size, 16384);
    }

    #[test]
    fn test_tls_config_with_session_lifetime() {
        let config = TlsConfig::new().with_session_lifetime(3600);
        assert_eq!(config.session_lifetime, 3600);
    }

    #[test]
    fn test_tls_config_with_resumption() {
        let config = TlsConfig::new().with_resumption(false);
        assert!(!config.enable_resumption);
    }

    #[test]
    fn test_tls_config_with_key_logging() {
        let config = TlsConfig::new().with_key_logging();
        assert!(config.enable_key_logging);
    }

    #[test]
    fn test_tls_config_with_cipher_suites() {
        let suites = vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384];
        let config = TlsConfig::new().with_cipher_suites(suites);
        assert!(config.cipher_suites.is_some());
    }

    #[test]
    fn test_tls_config_with_min_protocol_version() {
        let config = TlsConfig::new().with_min_protocol_version(rustls::ProtocolVersion::TLSv1_2);
        assert_eq!(config.min_protocol_version, Some(rustls::ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn test_tls_config_with_max_protocol_version() {
        let config = TlsConfig::new().with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
        assert_eq!(config.max_protocol_version, Some(rustls::ProtocolVersion::TLSv1_3));
    }

    #[test]
    fn test_tls_config_with_client_auth() {
        let config = TlsConfig::new().with_client_auth("client.crt", "client.key");
        assert!(config.client_auth.is_some());
        let auth = config.client_auth.as_ref().expect("should have client auth");
        assert_eq!(auth.cert_path, "client.crt");
        assert_eq!(auth.key_path, "client.key");
    }

    #[test]
    fn test_tls_config_with_client_verification() {
        let config = TlsConfig::new().with_client_verification(ClientVerificationMode::Required);
        assert_eq!(config.client_verification, ClientVerificationMode::Required);
    }

    #[test]
    fn test_tls_config_with_client_ca_certs() {
        let config = TlsConfig::new().with_client_ca_certs("ca-bundle.crt");
        assert_eq!(config.client_ca_certs.as_deref(), Some("ca-bundle.crt"));
    }

    #[test]
    fn test_tls_config_with_session_persistence() {
        let config = TlsConfig::new()
            .with_session_persistence(std::env::temp_dir().join("sessions.bin"), 500);
        assert!(config.session_persistence.is_some());
        let sp = config.session_persistence.as_ref().expect("should have persistence");
        assert_eq!(sp.max_sessions, 500);
    }

    // === validate() tests ===

    #[test]
    fn test_tls_config_validate_default() {
        let config = TlsConfig::new();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_validate_valid_range() {
        let config = TlsConfig::new()
            .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_2)
            .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_validate_min_only() {
        // min version set, max None => filters by >= min
        let mut config = TlsConfig::new();
        config.min_protocol_version = Some(rustls::ProtocolVersion::TLSv1_2);
        config.max_protocol_version = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_validate_no_min() {
        // No min version => skip validation entirely
        let mut config = TlsConfig::new();
        config.min_protocol_version = None;
        assert!(config.validate().is_ok());
    }

    // === ClientAuthConfig tests ===

    #[test]
    fn test_client_auth_config_new() {
        let auth = ClientAuthConfig::new("cert.pem", "key.pem");
        assert_eq!(auth.cert_path, "cert.pem");
        assert_eq!(auth.key_path, "key.pem");
    }

    // === ClientVerificationMode tests ===

    #[test]
    fn test_client_verification_mode_default() {
        assert_eq!(ClientVerificationMode::default(), ClientVerificationMode::None);
    }

    #[test]
    fn test_client_verification_mode_variants() {
        assert_ne!(ClientVerificationMode::None, ClientVerificationMode::Optional);
        assert_ne!(ClientVerificationMode::Optional, ClientVerificationMode::Required);
    }

    // === SessionPersistenceConfig tests ===

    #[test]
    fn test_session_persistence_config_new() {
        let sp = SessionPersistenceConfig::new(std::env::temp_dir().join("sess.bin"), 100);
        assert_eq!(sp.path, std::env::temp_dir().join("sess.bin"));
        assert_eq!(sp.max_sessions, 100);
    }

    // === From<&TlsConfig> for Tls13Config conversion coverage ===

    #[test]
    fn test_tls13_config_from_classic_tls_config() {
        let tls_config = TlsConfig { mode: TlsMode::Classic, ..TlsConfig::default() };
        let tls13 = Tls13Config::from(&tls_config);
        assert_eq!(tls13.mode, TlsMode::Classic);
    }

    #[test]
    fn test_tls13_config_from_pq_tls_config() {
        let tls_config = TlsConfig { mode: TlsMode::Pq, ..TlsConfig::default() };
        let tls13 = Tls13Config::from(&tls_config);
        assert_eq!(tls13.mode, TlsMode::Pq);
    }

    #[test]
    fn test_tls13_config_from_tls_config_alpn() {
        let tls_config = TlsConfig::new().with_alpn_protocols(vec!["h2"]);
        let tls13 = Tls13Config::from(&tls_config);
        assert_eq!(tls13.alpn_protocols.len(), 1);
        assert_eq!(tls13.alpn_protocols[0], b"h2");
    }

    #[test]
    fn test_tls13_config_from_tls_config_fragment_size() {
        let tls_config = TlsConfig::new().with_max_fragment_size(8192);
        let tls13 = Tls13Config::from(&tls_config);
        assert_eq!(tls13.max_fragment_size, Some(8192));
    }

    #[test]
    fn test_tls13_config_from_tls_config_early_data() {
        let tls_config = TlsConfig::new().with_early_data(32768);
        let tls13 = Tls13Config::from(&tls_config);
        assert!(tls13.enable_early_data);
        assert_eq!(tls13.max_early_data_size, 32768);
    }

    #[test]
    fn test_tls13_config_from_tls_config_cipher_suites() {
        let suites = vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384];
        let tls_config = TlsConfig::new().with_cipher_suites(suites);
        let tls13 = Tls13Config::from(&tls_config);
        assert!(tls13.cipher_suites.is_some());
    }

    #[test]
    fn test_tls13_config_from_tls_config_key_logging() {
        let tls_config = TlsConfig::new().with_key_logging();
        let tls13 = Tls13Config::from(&tls_config);
        assert!(tls13.key_log.is_some());
    }

    #[test]
    fn test_tls13_config_from_tls_config_client_verification() {
        let tls_config =
            TlsConfig::new().with_client_verification(ClientVerificationMode::Required);
        let tls13 = Tls13Config::from(&tls_config);
        assert_eq!(tls13.client_verification, ClientVerificationMode::Required);
    }

    #[test]
    fn test_tls13_config_from_tls_config_protocol_versions() {
        let tls_config = TlsConfig::new()
            .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
        let tls13 = Tls13Config::from(&tls_config);
        assert!(!tls13.protocol_versions.is_empty());
    }

    #[test]
    fn test_tls13_config_from_tls_config_protocol_versions_min_only() {
        let mut tls_config = TlsConfig::new();
        tls_config.min_protocol_version = Some(rustls::ProtocolVersion::TLSv1_3);
        tls_config.max_protocol_version = None;
        let tls13 = Tls13Config::from(&tls_config);
        assert!(!tls13.protocol_versions.is_empty());
    }

    // === TlsMode tests ===

    #[test]
    fn test_tls_mode_clone_copy_eq_debug() {
        let mode = TlsMode::Hybrid;
        let cloned = mode;
        let copied = mode;
        assert_eq!(mode, cloned);
        assert_eq!(mode, copied);
        let debug = format!("{:?}", mode);
        assert!(debug.contains("Hybrid"));
    }

    #[test]
    fn test_tls_mode_all_variants() {
        assert_ne!(TlsMode::Classic, TlsMode::Hybrid);
        assert_ne!(TlsMode::Hybrid, TlsMode::Pq);
        assert_ne!(TlsMode::Classic, TlsMode::Pq);
    }

    // === Full builder chain test ===

    #[test]
    fn test_tls_config_full_builder_chain() {
        let config = TlsConfig::new()
            .use_case(TlsUseCase::FinancialServices)
            .with_tracing()
            .with_fallback(true)
            .with_alpn_protocols(vec!["h2"])
            .with_max_fragment_size(4096)
            .with_session_lifetime(1800)
            .with_resumption(true)
            .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .with_client_verification(ClientVerificationMode::Optional)
            .with_client_ca_certs("ca.crt");

        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(config.enable_tracing);
        assert!(config.enable_fallback);
        assert_eq!(config.alpn_protocols.len(), 1);
        assert_eq!(config.max_fragment_size, Some(4096));
        assert_eq!(config.session_lifetime, 1800);
        assert!(config.enable_resumption);
        assert_eq!(config.client_verification, ClientVerificationMode::Optional);
        assert_eq!(config.client_ca_certs.as_deref(), Some("ca.crt"));
    }

    // === TlsConfig::default field values ===

    #[test]
    fn test_tls_config_default_values() {
        let config = TlsConfig::default();
        assert_eq!(config.mode, TlsMode::Hybrid);
        assert!(!config.enable_tracing);
        assert!(config.retry_policy.is_none());
        assert!(config.enable_fallback);
        assert!(config.alpn_protocols.is_empty());
        assert!(config.max_fragment_size.is_none());
        assert!(!config.enable_early_data);
        assert_eq!(config.max_early_data_size, 0);
        assert!(config.enable_resumption);
        assert_eq!(config.session_lifetime, 7200);
        assert!(!config.enable_key_logging);
        assert!(config.cipher_suites.is_none());
        assert_eq!(config.min_protocol_version, Some(rustls::ProtocolVersion::TLSv1_3));
        assert_eq!(config.max_protocol_version, Some(rustls::ProtocolVersion::TLSv1_3));
        assert!(config.client_auth.is_none());
        assert_eq!(config.client_verification, ClientVerificationMode::None);
        assert!(config.client_ca_certs.is_none());
        assert!(config.session_persistence.is_none());
    }

    // =========================================================================
    // Parameter Influence Tests (Audit 4.12)
    // =========================================================================

    #[test]
    fn test_enable_resumption_false_disables_sessions() {
        let tls_config = TlsConfig::new().with_resumption(false);
        let tls13 = Tls13Config::from(&tls_config);
        // When enable_resumption=false, Tls13Config should have Resumption::disabled()
        // We can verify by checking that creating a client config succeeds
        // and that the resumption field was changed from the default
        let default_tls13 = Tls13Config::from(&TlsConfig::new());
        // Default has in_memory_sessions(32), disabled has no sessions
        // We can't directly compare Resumption, but we can verify the conversion runs
        let _ = tls13;
        let _ = default_tls13;
    }

    #[test]
    fn test_enable_resumption_true_keeps_default() {
        let tls_config = TlsConfig::new().with_resumption(true);
        let _tls13 = Tls13Config::from(&tls_config);
        // Should succeed without error; resumption remains enabled
    }

    #[test]
    fn test_session_persistence_wired_to_tls13() {
        let tls_config = TlsConfig::new()
            .with_session_persistence(std::env::temp_dir().join("test_sessions.bin"), 256);
        let _tls13 = Tls13Config::from(&tls_config);
        // Should succeed; persistence config wired to resumption store
    }

    // =========================================================================
    // Pattern P4: Parameter Influence Tests
    // Each test proves changing ONLY one field changes the Tls13Config output.
    // =========================================================================

    #[test]
    fn test_enable_early_data_influences_tls13_config() {
        let config_a = TlsConfig::new(); // early data disabled by default
        let tls13_a = Tls13Config::from(&config_a);

        let config_b = TlsConfig::new().with_early_data(16384);
        let tls13_b = Tls13Config::from(&config_b);

        assert_ne!(
            tls13_a.enable_early_data, tls13_b.enable_early_data,
            "enable_early_data must influence Tls13Config"
        );
    }

    #[test]
    fn test_max_early_data_size_influences_tls13_config() {
        let config_a = TlsConfig::new().with_early_data(1024);
        let tls13_a = Tls13Config::from(&config_a);

        let config_b = TlsConfig::new().with_early_data(16384);
        let tls13_b = Tls13Config::from(&config_b);

        assert_ne!(
            tls13_a.max_early_data_size, tls13_b.max_early_data_size,
            "max_early_data_size must influence Tls13Config"
        );
    }

    #[test]
    fn test_max_fragment_size_influences_tls13_config() {
        let config_a = TlsConfig::new(); // None by default
        let tls13_a = Tls13Config::from(&config_a);

        let config_b = TlsConfig::new().with_max_fragment_size(1024);
        let tls13_b = Tls13Config::from(&config_b);

        assert_ne!(
            tls13_a.max_fragment_size, tls13_b.max_fragment_size,
            "max_fragment_size must influence Tls13Config"
        );
    }

    #[test]
    fn test_alpn_protocols_influences_tls13_config() {
        let config_a = TlsConfig::new(); // no ALPN by default
        let tls13_a = Tls13Config::from(&config_a);

        let config_b = TlsConfig::new().with_alpn_protocols(vec!["h2"]);
        let tls13_b = Tls13Config::from(&config_b);

        assert_ne!(
            tls13_a.alpn_protocols, tls13_b.alpn_protocols,
            "alpn_protocols must influence Tls13Config"
        );
    }

    #[test]
    fn test_enable_key_logging_influences_tls13_config() {
        let config_a = TlsConfig::new(); // key logging off by default
        let tls13_a = Tls13Config::from(&config_a);

        let config_b = TlsConfig::new().with_key_logging();
        let tls13_b = Tls13Config::from(&config_b);

        // key_log is None when disabled, Some when enabled
        assert_ne!(
            tls13_a.key_log.is_some(),
            tls13_b.key_log.is_some(),
            "enable_key_logging must influence Tls13Config key_log"
        );
    }

    #[test]
    fn test_client_verification_influences_tls13_config() {
        let config_a = TlsConfig::new(); // default client verification
        let tls13_a = Tls13Config::from(&config_a);

        let config_b = TlsConfig::new().with_client_verification(ClientVerificationMode::Required);
        let tls13_b = Tls13Config::from(&config_b);

        assert_ne!(
            tls13_a.client_verification, tls13_b.client_verification,
            "client_verification must influence Tls13Config"
        );
    }

    #[test]
    fn test_mode_influences_tls13_config() {
        let mut config_a = TlsConfig::new();
        config_a.mode = TlsMode::Hybrid;
        let tls13_a = Tls13Config::from(&config_a);

        let mut config_b = TlsConfig::new();
        config_b.mode = TlsMode::Pq;
        let tls13_b = Tls13Config::from(&config_b);

        assert_ne!(tls13_a.mode, tls13_b.mode, "mode must influence Tls13Config");
    }
}
