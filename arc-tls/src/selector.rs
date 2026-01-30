#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! TLS Policy Engine
//!
//! Provides intelligent policy-based selection of TLS modes (Classic, Hybrid, PQ)
//! based on use case, security requirements, performance preferences, and
//! connection constraints.
//!
//! ## Quick Start
//!
//! ```rust
//! use arc_tls::{TlsPolicyEngine, TlsUseCase, TlsConfig};
//!
//! // Auto-select mode by use case
//! let mode = TlsPolicyEngine::recommend_mode(TlsUseCase::WebServer);
//!
//! // Create config for specific use case
//! let config = TlsConfig::new().use_case(TlsUseCase::FinancialServices);
//! ```

use crate::{TlsConfig, TlsMode};
use arc_core::{PerformancePreference, SecurityLevel};

// =============================================================================
// HYBRID TLS SCHEMES (Default) - PQ + Classical for defense in depth
// =============================================================================

/// Default hybrid TLS key exchange - X25519 + ML-KEM-768
pub const DEFAULT_TLS_KEX: &str = "X25519MLKEM768";
/// Default hybrid TLS scheme identifier
pub const DEFAULT_TLS_SCHEME: &str = "hybrid-x25519-ml-kem-768";

/// Hybrid TLS scheme using X25519 + ML-KEM-512.
pub const HYBRID_TLS_512: &str = "hybrid-x25519-ml-kem-512";
/// Hybrid TLS scheme using X25519 + ML-KEM-768.
pub const HYBRID_TLS_768: &str = "hybrid-x25519-ml-kem-768";
/// Hybrid TLS scheme using X25519 + ML-KEM-1024.
pub const HYBRID_TLS_1024: &str = "hybrid-x25519-ml-kem-1024";

// =============================================================================
// PQ-ONLY TLS SCHEMES - Pure post-quantum, no classical fallback
// =============================================================================

/// Default PQ-only TLS key exchange - ML-KEM-768 only
pub const DEFAULT_PQ_TLS_KEX: &str = "MLKEM768";
/// Default PQ-only TLS scheme identifier
pub const DEFAULT_PQ_TLS_SCHEME: &str = "pq-ml-kem-768";

/// PQ-only TLS scheme using ML-KEM-512.
pub const PQ_TLS_512: &str = "pq-ml-kem-512";
/// PQ-only TLS scheme using ML-KEM-768.
pub const PQ_TLS_768: &str = "pq-ml-kem-768";
/// PQ-only TLS scheme using ML-KEM-1024.
pub const PQ_TLS_1024: &str = "pq-ml-kem-1024";

// =============================================================================
// CLASSICAL TLS SCHEMES - For legacy/compatibility only
// =============================================================================

/// Classical TLS key exchange - X25519 only (not quantum-safe)
pub const CLASSICAL_TLS_KEX: &str = "X25519";
/// Classical TLS scheme identifier
pub const CLASSICAL_TLS_SCHEME: &str = "classic-x25519";

/// TLS-specific use cases for automatic mode selection
///
/// Each use case maps to a recommended TLS mode based on:
/// - Security requirements
/// - Performance constraints
/// - Compatibility needs
/// - Regulatory requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsUseCase {
    /// Web server serving public clients - Hybrid recommended
    /// Balances security with broad client compatibility
    WebServer,
    /// Internal microservice communication - Hybrid recommended
    /// Zero-trust internal security with PQ protection
    InternalService,
    /// API gateway or reverse proxy - Hybrid recommended
    /// Must support diverse clients while maintaining security
    ApiGateway,
    /// IoT or embedded devices - Classic recommended
    /// Resource constraints may limit PQ capability
    IoT,
    /// Legacy system integration - Classic recommended
    /// Maximum compatibility with older systems
    LegacyIntegration,
    /// Financial services - Hybrid recommended
    /// Compliance requirements plus long-term PQ protection
    FinancialServices,
    /// Healthcare systems - Hybrid recommended
    /// HIPAA compliance plus quantum-resistant protection
    Healthcare,
    /// Government or high-security - PQ recommended
    /// Maximum quantum resistance for classified data
    Government,
    /// Database connections - Hybrid recommended
    /// Long-lived connections need future-proof protection
    DatabaseConnection,
    /// Real-time streaming (video, audio) - Classic recommended
    /// Low latency is critical, handshake overhead must be minimal
    RealTimeStreaming,
}

impl TlsUseCase {
    /// Get a brief description of this use case
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::WebServer => "Web server serving public clients",
            Self::InternalService => "Internal microservice communication",
            Self::ApiGateway => "API gateway or reverse proxy",
            Self::IoT => "IoT or embedded devices",
            Self::LegacyIntegration => "Legacy system integration",
            Self::FinancialServices => "Financial services",
            Self::Healthcare => "Healthcare systems",
            Self::Government => "Government or high-security",
            Self::DatabaseConnection => "Database connections",
            Self::RealTimeStreaming => "Real-time streaming",
        }
    }

    /// Get all available use cases
    #[must_use]
    pub fn all() -> &'static [TlsUseCase] {
        &[
            Self::WebServer,
            Self::InternalService,
            Self::ApiGateway,
            Self::IoT,
            Self::LegacyIntegration,
            Self::FinancialServices,
            Self::Healthcare,
            Self::Government,
            Self::DatabaseConnection,
            Self::RealTimeStreaming,
        ]
    }
}

/// Connection constraints affecting TLS mode selection
///
/// These constraints can override or influence the default mode
/// selection based on network or client limitations.
#[derive(Debug, Clone, Default)]
pub struct TlsConstraints {
    /// Maximum acceptable handshake latency in milliseconds
    /// Lower values favor Classic mode (smaller key exchange)
    pub max_handshake_latency_ms: Option<u64>,
    /// Whether the client is known to support PQ algorithms
    /// If false, forces Classic mode
    pub client_supports_pq: Option<bool>,
    /// Require maximum backward compatibility
    /// If true, prefers Classic mode
    pub require_compatibility: bool,
    /// Maximum acceptable ClientHello size in bytes
    /// ML-KEM adds ~1184 bytes to ClientHello
    pub max_client_hello_size: Option<usize>,
}

impl TlsConstraints {
    /// Create constraints with maximum compatibility
    #[must_use]
    pub fn maximum_compatibility() -> Self {
        Self {
            max_handshake_latency_ms: Some(50),
            client_supports_pq: Some(false),
            require_compatibility: true,
            max_client_hello_size: Some(512),
        }
    }

    /// Create constraints for high-security environments
    #[must_use]
    pub fn high_security() -> Self {
        Self {
            max_handshake_latency_ms: None,
            client_supports_pq: Some(true),
            require_compatibility: false,
            max_client_hello_size: None,
        }
    }

    /// Check if constraints require classic mode
    #[must_use]
    pub fn requires_classic(&self) -> bool {
        // Client doesn't support PQ
        if self.client_supports_pq == Some(false) {
            return true;
        }
        // Strict compatibility requirement
        if self.require_compatibility {
            return true;
        }
        // Very strict latency requirement (< 20ms excludes PQ overhead)
        if let Some(latency) = self.max_handshake_latency_ms
            && latency < 20
        {
            return true;
        }
        // Very strict size constraint (ML-KEM needs ~1184 bytes)
        if let Some(max_size) = self.max_client_hello_size
            && max_size < 1500
        {
            return true;
        }
        false
    }

    /// Check if constraints allow PQ mode
    #[must_use]
    pub fn allows_pq(&self) -> bool {
        // Must explicitly support PQ or be unknown
        if self.client_supports_pq == Some(false) {
            return false;
        }
        // Can't require strict compatibility
        if self.require_compatibility {
            return false;
        }
        true
    }
}

/// Context for TLS mode selection
///
/// Combines security level, performance preference, use case,
/// and constraints for intelligent mode selection.
#[derive(Debug, Clone)]
pub struct TlsContext {
    /// Desired security level
    pub security_level: SecurityLevel,
    /// Performance vs security tradeoff preference
    pub performance_preference: PerformancePreference,
    /// Optional specific use case
    pub use_case: Option<TlsUseCase>,
    /// Whether PQ algorithms are available in the runtime
    pub pq_available: bool,
    /// Connection-specific constraints
    pub constraints: TlsConstraints,
}

impl Default for TlsContext {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::High,
            performance_preference: PerformancePreference::Balanced,
            use_case: None,
            pq_available: crate::pq_enabled(),
            constraints: TlsConstraints::default(),
        }
    }
}

impl TlsContext {
    /// Create context with security level
    #[must_use]
    pub fn with_security_level(security_level: SecurityLevel) -> Self {
        Self { security_level, ..Default::default() }
    }

    /// Create context for a specific use case
    #[must_use]
    pub fn with_use_case(use_case: TlsUseCase) -> Self {
        Self { use_case: Some(use_case), ..Default::default() }
    }

    /// Create context with all parameters
    #[must_use]
    pub fn new(
        security_level: SecurityLevel,
        performance_preference: PerformancePreference,
        use_case: Option<TlsUseCase>,
        pq_available: bool,
        constraints: TlsConstraints,
    ) -> Self {
        Self { security_level, performance_preference, use_case, pq_available, constraints }
    }

    /// Set the security level
    #[must_use]
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    /// Set the performance preference
    #[must_use]
    pub fn performance_preference(mut self, pref: PerformancePreference) -> Self {
        self.performance_preference = pref;
        self
    }

    /// Set the use case
    #[must_use]
    pub fn use_case(mut self, use_case: TlsUseCase) -> Self {
        self.use_case = Some(use_case);
        self
    }

    /// Set connection constraints
    #[must_use]
    pub fn constraints(mut self, constraints: TlsConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Set PQ availability
    #[must_use]
    pub fn pq_available(mut self, available: bool) -> Self {
        self.pq_available = available;
        self
    }
}

/// TLS Mode Selector
///
/// Provides intelligent automatic selection of TLS modes based on
/// various factors including use case, security level, performance
/// requirements, and connection constraints.
pub struct TlsPolicyEngine;

impl TlsPolicyEngine {
    /// Recommend TLS mode based on use case
    ///
    /// # Use Case Mappings
    ///
    /// | Use Case | Mode | Rationale |
    /// |----------|------|-----------|
    /// | WebServer | Hybrid | Balance security + compatibility |
    /// | InternalService | Hybrid | Zero-trust internal security |
    /// | ApiGateway | Hybrid | Client compatibility |
    /// | IoT | Classic | Resource constraints |
    /// | LegacyIntegration | Classic | Maximum compatibility |
    /// | FinancialServices | Hybrid | Compliance + PQ protection |
    /// | Healthcare | Hybrid | HIPAA + PQ protection |
    /// | Government | Pq | Maximum quantum resistance |
    /// | DatabaseConnection | Hybrid | Data protection |
    /// | RealTimeStreaming | Classic | Low latency priority |
    #[must_use]
    pub fn recommend_mode(use_case: TlsUseCase) -> TlsMode {
        match use_case {
            TlsUseCase::WebServer => TlsMode::Hybrid,
            TlsUseCase::InternalService => TlsMode::Hybrid,
            TlsUseCase::ApiGateway => TlsMode::Hybrid,
            TlsUseCase::IoT => TlsMode::Classic,
            TlsUseCase::LegacyIntegration => TlsMode::Classic,
            TlsUseCase::FinancialServices => TlsMode::Hybrid,
            TlsUseCase::Healthcare => TlsMode::Hybrid,
            TlsUseCase::Government => TlsMode::Pq,
            TlsUseCase::DatabaseConnection => TlsMode::Hybrid,
            TlsUseCase::RealTimeStreaming => TlsMode::Classic,
        }
    }

    /// Select TLS mode based on security level
    ///
    /// | Security Level | Mode |
    /// |---------------|------|
    /// | Maximum | Pq |
    /// | High | Hybrid |
    /// | Standard | Hybrid |
    /// | Quantum | Pq |
    #[must_use]
    pub fn select_by_security_level(level: SecurityLevel) -> TlsMode {
        match level {
            // Quantum: PQ-only (no classical key exchange)
            SecurityLevel::Quantum => TlsMode::Pq,
            // All other levels: Hybrid (PQ + classical for defense-in-depth)
            SecurityLevel::Standard | SecurityLevel::High | SecurityLevel::Maximum => TlsMode::Hybrid,
        }
    }

    // =========================================================================
    // PQ-ONLY SELECTORS - Pure post-quantum, no classical component
    // =========================================================================

    /// Select PQ-only TLS scheme (no classical X25519 component).
    ///
    /// Use this when you want pure post-quantum without hybrid fallback.
    ///
    /// | Security Level | Scheme |
    /// |---------------|--------|
    /// | Standard | pq-ml-kem-512 |
    /// | High | pq-ml-kem-768 |
    /// | Maximum/Quantum | pq-ml-kem-1024 |
    #[must_use]
    pub fn select_pq_scheme(level: SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Standard => PQ_TLS_512,
            SecurityLevel::High => PQ_TLS_768,
            SecurityLevel::Maximum | SecurityLevel::Quantum => PQ_TLS_1024,
        }
    }

    /// Select PQ-only key exchange algorithm based on security level.
    ///
    /// Returns the ML-KEM variant without X25519 hybrid.
    #[must_use]
    pub fn select_pq_kex(level: SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Standard => "MLKEM512",
            SecurityLevel::High => "MLKEM768",
            SecurityLevel::Maximum | SecurityLevel::Quantum => "MLKEM1024",
        }
    }

    // =========================================================================
    // HYBRID SELECTORS - PQ + Classical (default)
    // =========================================================================

    /// Select hybrid TLS scheme based on security level.
    ///
    /// | Security Level | Scheme |
    /// |---------------|--------|
    /// | Standard | hybrid-x25519-ml-kem-512 |
    /// | High | hybrid-x25519-ml-kem-768 |
    /// | Maximum/Quantum | hybrid-x25519-ml-kem-1024 |
    #[must_use]
    pub fn select_hybrid_scheme(level: SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Standard => HYBRID_TLS_512,
            SecurityLevel::High => HYBRID_TLS_768,
            SecurityLevel::Maximum | SecurityLevel::Quantum => HYBRID_TLS_1024,
        }
    }

    /// Select hybrid key exchange algorithm based on security level.
    ///
    /// Returns the X25519 + ML-KEM variant.
    #[must_use]
    pub fn select_hybrid_kex(level: SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Standard => "X25519MLKEM512",
            SecurityLevel::High => "X25519MLKEM768",
            SecurityLevel::Maximum | SecurityLevel::Quantum => "X25519MLKEM1024",
        }
    }

    // =========================================================================
    // SCHEME UTILITIES
    // =========================================================================

    /// Get the scheme identifier string for a TLS mode and security level.
    #[must_use]
    pub fn get_scheme_identifier(mode: TlsMode, level: SecurityLevel) -> &'static str {
        match mode {
            TlsMode::Classic => CLASSICAL_TLS_SCHEME,
            TlsMode::Hybrid => Self::select_hybrid_scheme(level),
            TlsMode::Pq => Self::select_pq_scheme(level),
        }
    }

    /// Get the key exchange algorithm for a TLS mode and security level.
    #[must_use]
    pub fn get_kex_algorithm(mode: TlsMode, level: SecurityLevel) -> &'static str {
        match mode {
            TlsMode::Classic => CLASSICAL_TLS_KEX,
            TlsMode::Hybrid => Self::select_hybrid_kex(level),
            TlsMode::Pq => Self::select_pq_kex(level),
        }
    }

    /// Returns the default hybrid scheme (no context analysis).
    #[must_use]
    pub fn default_scheme() -> &'static str {
        DEFAULT_TLS_SCHEME
    }

    /// Returns the default PQ-only scheme.
    #[must_use]
    pub fn default_pq_scheme() -> &'static str {
        DEFAULT_PQ_TLS_SCHEME
    }

    /// Select TLS mode balancing security and performance
    ///
    /// This method considers both security requirements and
    /// performance preferences to find an appropriate balance.
    #[must_use]
    pub fn select_balanced(security: SecurityLevel, performance: PerformancePreference) -> TlsMode {
        match (security, performance) {
            // Quantum: always PQ-only (no classical key exchange)
            (SecurityLevel::Quantum, _) => TlsMode::Pq,
            // All other levels: Hybrid for defense-in-depth
            // Speed preference with Standard may prefer smaller keys but still Hybrid
            (SecurityLevel::Standard, PerformancePreference::Speed) => TlsMode::Hybrid,
            (SecurityLevel::High, PerformancePreference::Speed) => TlsMode::Hybrid,
            (SecurityLevel::Maximum, PerformancePreference::Speed) => TlsMode::Hybrid,
            // Memory preference uses Hybrid (PQ keys are larger but manageable)
            (_, PerformancePreference::Memory) => TlsMode::Hybrid,
            // Balanced preference defaults to Hybrid for future-proofing
            (_, PerformancePreference::Balanced) => TlsMode::Hybrid,
        }
    }

    /// Select TLS mode with full context awareness
    ///
    /// This is the most comprehensive selection method, considering:
    /// - Security level requirements
    /// - Performance preferences
    /// - Use case recommendations
    /// - Runtime PQ availability
    /// - Connection-specific constraints
    ///
    /// # Selection Priority
    ///
    /// 1. If constraints require Classic → Classic
    /// 2. If PQ not available → Classic
    /// 3. If use case specified → use case recommendation
    /// 4. Otherwise → balanced selection based on security/performance
    #[must_use]
    pub fn select_with_context(ctx: &TlsContext) -> TlsMode {
        // Check hard constraints first
        if ctx.constraints.requires_classic() {
            return TlsMode::Classic;
        }

        // PQ must be available for non-Classic modes
        if !ctx.pq_available {
            return TlsMode::Classic;
        }

        // If use case specified, start with that recommendation
        let base_mode = if let Some(use_case) = ctx.use_case {
            Self::recommend_mode(use_case)
        } else {
            Self::select_balanced(ctx.security_level.clone(), ctx.performance_preference.clone())
        };

        // Apply security level override for Quantum (PQ-only)
        if ctx.security_level == SecurityLevel::Quantum && ctx.constraints.allows_pq() {
            return TlsMode::Pq;
        }

        // Downgrade PQ to Hybrid if constraints don't fully allow PQ
        if base_mode == TlsMode::Pq && !ctx.constraints.allows_pq() {
            return TlsMode::Hybrid;
        }

        base_mode
    }

    /// Create a TlsConfig from a TlsContext
    ///
    /// This creates a fully configured TlsConfig with the automatically
    /// selected mode and appropriate default settings.
    #[must_use]
    pub fn create_config(ctx: &TlsContext) -> TlsConfig {
        let mode = Self::select_with_context(ctx);

        let mut config = TlsConfig::default();
        config.mode = mode;

        // Apply performance-related settings based on preference
        match ctx.performance_preference {
            PerformancePreference::Speed => {
                // Disable features that add latency
                config.enable_fallback = false;
            }
            PerformancePreference::Memory => {
                // Limit buffer sizes
                config.max_fragment_size = Some(4096);
            }
            PerformancePreference::Balanced => {
                // Keep defaults
            }
        }

        // Apply security-related settings based on level
        match ctx.security_level {
            SecurityLevel::Quantum | SecurityLevel::Maximum => {
                // Strictest settings
                config.enable_early_data = false;
                config.require_secure_renegotiation = true;
            }
            SecurityLevel::High => {
                config.require_secure_renegotiation = true;
            }
            SecurityLevel::Standard => {
                // Allow more flexible settings for resource-constrained devices
            }
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommend_mode_webserver() {
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::WebServer), TlsMode::Hybrid);
    }

    #[test]
    fn test_recommend_mode_iot() {
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::IoT), TlsMode::Classic);
    }

    #[test]
    fn test_recommend_mode_government() {
        assert_eq!(TlsPolicyEngine::recommend_mode(TlsUseCase::Government), TlsMode::Pq);
    }

    #[test]
    fn test_select_by_security_level_quantum() {
        // Quantum is PQ-only
        assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Quantum), TlsMode::Pq);
    }

    #[test]
    fn test_select_by_security_level_maximum() {
        // Maximum is Hybrid (not PQ-only) for defense-in-depth
        assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Maximum), TlsMode::Hybrid);
    }

    #[test]
    fn test_select_by_security_level_standard() {
        // Standard is Hybrid
        assert_eq!(TlsPolicyEngine::select_by_security_level(SecurityLevel::Standard), TlsMode::Hybrid);
    }

    #[test]
    fn test_select_balanced_quantum_security() {
        // Quantum always uses PQ-only
        assert_eq!(
            TlsPolicyEngine::select_balanced(SecurityLevel::Quantum, PerformancePreference::Speed),
            TlsMode::Pq
        );
    }

    #[test]
    fn test_select_balanced_standard_security() {
        // Standard uses Hybrid for defense-in-depth
        assert_eq!(
            TlsPolicyEngine::select_balanced(SecurityLevel::Standard, PerformancePreference::Balanced),
            TlsMode::Hybrid
        );
    }

    #[test]
    fn test_context_default() {
        let ctx = TlsContext::default();
        assert_eq!(ctx.security_level, SecurityLevel::High);
        assert_eq!(ctx.performance_preference, PerformancePreference::Balanced);
    }

    #[test]
    fn test_constraints_requires_classic() {
        let constraints = TlsConstraints::maximum_compatibility();
        assert!(constraints.requires_classic());
    }

    #[test]
    fn test_constraints_allows_pq() {
        let constraints = TlsConstraints::high_security();
        assert!(constraints.allows_pq());
    }

    #[test]
    fn test_use_case_all() {
        let all = TlsUseCase::all();
        assert_eq!(all.len(), 10);
    }

    // PQ-only selector tests
    #[test]
    fn test_select_pq_scheme_maximum() {
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Maximum), PQ_TLS_1024);
    }

    #[test]
    fn test_select_pq_scheme_high() {
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::High), PQ_TLS_768);
    }

    #[test]
    fn test_select_pq_scheme_standard() {
        assert_eq!(TlsPolicyEngine::select_pq_scheme(SecurityLevel::Standard), PQ_TLS_512);
    }

    #[test]
    fn test_select_pq_kex_maximum() {
        assert_eq!(TlsPolicyEngine::select_pq_kex(SecurityLevel::Maximum), "MLKEM1024");
    }

    // Hybrid selector tests
    #[test]
    fn test_select_hybrid_scheme_maximum() {
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::Maximum), HYBRID_TLS_1024);
    }

    #[test]
    fn test_select_hybrid_scheme_high() {
        assert_eq!(TlsPolicyEngine::select_hybrid_scheme(SecurityLevel::High), HYBRID_TLS_768);
    }

    #[test]
    fn test_select_hybrid_kex_high() {
        assert_eq!(TlsPolicyEngine::select_hybrid_kex(SecurityLevel::High), "X25519MLKEM768");
    }

    // Scheme utilities tests
    #[test]
    fn test_get_scheme_identifier_classic() {
        assert_eq!(
            TlsPolicyEngine::get_scheme_identifier(TlsMode::Classic, SecurityLevel::High),
            CLASSICAL_TLS_SCHEME
        );
    }

    #[test]
    fn test_get_scheme_identifier_hybrid() {
        assert_eq!(
            TlsPolicyEngine::get_scheme_identifier(TlsMode::Hybrid, SecurityLevel::High),
            HYBRID_TLS_768
        );
    }

    #[test]
    fn test_get_scheme_identifier_pq() {
        assert_eq!(
            TlsPolicyEngine::get_scheme_identifier(TlsMode::Pq, SecurityLevel::Maximum),
            PQ_TLS_1024
        );
    }

    #[test]
    fn test_get_kex_algorithm_classic() {
        assert_eq!(
            TlsPolicyEngine::get_kex_algorithm(TlsMode::Classic, SecurityLevel::High),
            CLASSICAL_TLS_KEX
        );
    }

    #[test]
    fn test_get_kex_algorithm_pq() {
        assert_eq!(
            TlsPolicyEngine::get_kex_algorithm(TlsMode::Pq, SecurityLevel::High),
            "MLKEM768"
        );
    }

    #[test]
    fn test_default_scheme() {
        assert_eq!(TlsPolicyEngine::default_scheme(), DEFAULT_TLS_SCHEME);
    }

    #[test]
    fn test_default_pq_scheme() {
        assert_eq!(TlsPolicyEngine::default_pq_scheme(), DEFAULT_PQ_TLS_SCHEME);
    }

    // Constants tests
    #[test]
    fn test_constants_contain_expected_values() {
        assert!(DEFAULT_TLS_SCHEME.contains("hybrid"));
        assert!(DEFAULT_PQ_TLS_SCHEME.contains("pq"));
        assert!(CLASSICAL_TLS_SCHEME.contains("classic"));
    }
}
