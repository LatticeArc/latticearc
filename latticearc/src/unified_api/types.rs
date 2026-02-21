//! Fundamental cryptographic types for LatticeArc Core.
//!
//! Most types are defined in [`crate::types::types`] and re-exported here.
//! `CryptoConfig<'a>` stays here because it references `VerifiedSession`
//! which depends on Ed25519 FFI.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

// Re-export all pure-Rust types from arc-types
pub use crate::types::types::*;

use crate::unified_api::zero_trust::VerifiedSession;

/// Returns the default compliance mode for a given use case.
///
/// Regulated use cases automatically get FIPS 140-3 compliance,
/// which will be validated at operation time (failing gracefully
/// if the `fips` feature is not enabled).
fn default_compliance_for_use_case(use_case: &UseCase) -> ComplianceMode {
    match use_case {
        UseCase::GovernmentClassified
        | UseCase::HealthcareRecords
        | UseCase::PaymentCard
        | UseCase::FinancialTransactions => ComplianceMode::Fips140_3,
        _ => ComplianceMode::Default,
    }
}

// ============================================================================
// Unified Crypto Configuration (stays in arc-core due to VerifiedSession FFI dep)
// ============================================================================

/// Unified configuration for cryptographic operations.
///
/// Provides a single, consistent way to configure encrypt, decrypt, sign, and verify
/// operations. Uses a builder pattern for ergonomic configuration.
///
/// # Examples
///
/// ```rust,no_run
/// # use latticearc::unified_api::{encrypt, CryptoConfig, UseCase, SecurityLevel, VerifiedSession, generate_keypair};
/// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
/// # let data = b"secret";
/// # let key = [0u8; 32];
/// // Simple - all defaults (High security, no session)
/// encrypt(data, &key, CryptoConfig::new())?;
///
/// // With Zero Trust session
/// # let (pk, sk) = generate_keypair()?;
/// let session = VerifiedSession::establish(&pk, sk.as_ref())?;
/// encrypt(data, &key, CryptoConfig::new().session(&session))?;
///
/// // With use case (recommended - library picks optimal algorithm)
/// encrypt(data, &key, CryptoConfig::new()
///     .session(&session)
///     .use_case(UseCase::FileStorage))?;
///
/// // With security level (manual control)
/// encrypt(data, &key, CryptoConfig::new()
///     .session(&session)
///     .security_level(SecurityLevel::Maximum))?;
///
/// // With FIPS compliance (requires `fips` feature)
/// use latticearc::types::types::ComplianceMode;
/// encrypt(data, &key, CryptoConfig::new()
///     .compliance(ComplianceMode::Fips140_3))?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CryptoConfig<'a> {
    /// Optional Zero Trust verified session.
    /// If None, operates in unverified mode.
    session: Option<&'a VerifiedSession>,
    /// Algorithm selection mode (use case or security level).
    selection: AlgorithmSelection,
    /// Compliance mode for regulatory requirements.
    compliance: ComplianceMode,
    /// Whether the user explicitly set compliance (vs. auto-set by use_case).
    compliance_explicit: bool,
}

impl<'a> Default for CryptoConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CryptoConfig<'a> {
    /// Creates new configuration with defaults (High security, no session, no compliance restrictions).
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: None,
            selection: AlgorithmSelection::default(),
            compliance: ComplianceMode::Default,
            compliance_explicit: false,
        }
    }

    /// Sets the Zero Trust verified session.
    ///
    /// When set, the session is validated before each operation.
    /// Operations will fail if the session has expired.
    #[must_use]
    pub fn session(mut self, session: &'a VerifiedSession) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets the use case for automatic algorithm selection (recommended).
    ///
    /// The library will choose the optimal algorithm for this use case.
    /// This overrides any previously set security level.
    ///
    /// Regulated use cases (`GovernmentClassified`, `HealthcareRecords`, `PaymentCard`,
    /// `FinancialTransactions`) automatically set FIPS 140-3 compliance unless the user
    /// has explicitly called `.compliance()` to override.
    #[must_use]
    pub fn use_case(mut self, use_case: UseCase) -> Self {
        // Auto-set compliance for regulated use cases, unless explicitly overridden
        if !self.compliance_explicit {
            self.compliance = default_compliance_for_use_case(&use_case);
        }
        self.selection = AlgorithmSelection::UseCase(use_case);
        self
    }

    /// Sets the security level for manual algorithm selection.
    ///
    /// Use this when your use case doesn't fit predefined options.
    /// This overrides any previously set use case.
    #[must_use]
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.selection = AlgorithmSelection::SecurityLevel(level);
        self
    }

    /// Forces a specific cryptographic scheme category.
    ///
    /// Bypasses automatic algorithm selection (use case or security level)
    /// and directly selects the specified scheme type.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use latticearc::unified_api::{CryptoConfig, encrypt};
    /// # use latticearc::types::types::CryptoScheme;
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// let key = [0u8; 32];
    /// // Force post-quantum encryption
    /// encrypt(b"data", &key, CryptoConfig::new()
    ///     .force_scheme(CryptoScheme::PostQuantum))?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn force_scheme(mut self, scheme: CryptoScheme) -> Self {
        self.selection = AlgorithmSelection::ForcedScheme(scheme);
        self
    }

    /// Sets the compliance mode for regulatory requirements.
    ///
    /// When set explicitly, this overrides any auto-compliance from `.use_case()`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use latticearc::unified_api::{CryptoConfig, encrypt};
    /// # use latticearc::types::types::ComplianceMode;
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// let key = [0u8; 32];
    /// // Explicitly require FIPS compliance
    /// encrypt(b"data", &key, CryptoConfig::new()
    ///     .compliance(ComplianceMode::Fips140_3))?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn compliance(mut self, mode: ComplianceMode) -> Self {
        self.compliance = mode;
        self.compliance_explicit = true;
        self
    }

    /// Returns the session if set.
    #[must_use]
    pub fn get_session(&self) -> Option<&'a VerifiedSession> {
        self.session
    }

    /// Returns the algorithm selection mode.
    #[must_use]
    pub fn get_selection(&self) -> &AlgorithmSelection {
        &self.selection
    }

    /// Returns the compliance mode.
    #[must_use]
    pub fn get_compliance(&self) -> &ComplianceMode {
        &self.compliance
    }

    /// Returns true if a session is set (verified mode).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.session.is_some()
    }

    /// Check if a scheme string is acceptable under the current compliance mode.
    ///
    /// This enforces compliance policies against the algorithm encoded in
    /// ciphertext or signature metadata. Following the OpenSSL model, compliance
    /// is enforced on both encrypt/sign and decrypt/verify sides.
    ///
    /// # Scheme classification
    ///
    /// | Compliance | Allowed schemes | Rejected schemes |
    /// |------------|-----------------|------------------|
    /// | Default    | All             | None             |
    /// | FIPS 140-3 | AES-256-GCM, ML-KEM-*, ML-DSA-*, SLH-DSA-*, hybrid-* | ChaCha20-Poly1305 |
    /// | CNSA 2.0   | ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-*, hybrid-* | Ed25519, AES-256-GCM (pure classical) |
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ComplianceViolation` if the scheme is not permitted
    /// under the active compliance mode.
    pub fn validate_scheme_compliance(
        &self,
        scheme: &str,
    ) -> crate::unified_api::error::Result<()> {
        use crate::unified_api::error::CoreError;

        match self.compliance {
            ComplianceMode::Default => Ok(()),
            ComplianceMode::Fips140_3 => {
                // ChaCha20-Poly1305 is not FIPS 140-3 validated
                if scheme.contains("chacha") {
                    return Err(CoreError::ComplianceViolation(format!(
                        "Scheme '{}' is not FIPS 140-3 approved. \
                         Use AES-256-GCM or a FIPS-validated algorithm.",
                        scheme
                    )));
                }
                Ok(())
            }
            ComplianceMode::Cnsa2_0 => {
                // CNSA 2.0 mandates post-quantum algorithms.
                // Pure classical schemes (ed25519, aes-256-gcm standalone) are rejected.
                // Hybrid schemes (ml-dsa-*-ed25519, ml-kem-*-x25519) are allowed
                // as transitional per NIST SP 800-227.
                if scheme == "ed25519" || scheme == "aes-256-gcm" {
                    return Err(CoreError::ComplianceViolation(format!(
                        "Scheme '{}' is not permitted under CNSA 2.0 (post-quantum required). \
                         Use ML-KEM, ML-DSA, SLH-DSA, FN-DSA, or a hybrid scheme.",
                        scheme
                    )));
                }
                Ok(())
            }
        }
    }

    /// Validates the configuration.
    ///
    /// Checks:
    /// 1. Session expiry (if present)
    /// 2. FIPS feature availability (if compliance mode requires it)
    /// 3. CNSA 2.0 security level requirements (must be `Quantum`)
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SessionExpired` if the session has expired.
    /// Returns `CoreError::FeatureNotAvailable` if compliance mode requires FIPS
    /// but the `fips` feature is not enabled.
    /// Returns `CoreError::ConfigurationError` if CNSA 2.0 is set but the security
    /// level is not `Quantum`.
    pub fn validate(&self) -> crate::unified_api::error::Result<()> {
        use crate::unified_api::error::CoreError;

        // 1. Session expiry check
        if let Some(session) = self.session {
            session.verify_valid()?;
        }

        // 2. FIPS availability check
        if self.compliance.requires_fips() && !fips_available() {
            return Err(CoreError::FeatureNotAvailable(format!(
                "{:?} compliance requires the `fips` feature. \
                 Rebuild with: latticearc = {{ version = \"0.2\", features = [\"fips\"] }}",
                self.compliance
            )));
        }

        // 3. CNSA 2.0 requires SecurityLevel::Quantum (PQ-only)
        if matches!(self.compliance, ComplianceMode::Cnsa2_0)
            && let AlgorithmSelection::SecurityLevel(ref level) = self.selection
            && !matches!(level, SecurityLevel::Quantum)
        {
            return Err(CoreError::ConfigurationError(
                "CNSA 2.0 compliance requires SecurityLevel::Quantum (PQ-only)".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Tests for types that moved to arc-types

    #[test]
    fn test_zeroized_bytes_new() {
        let data = vec![1u8, 2, 3, 4, 5];
        let zb = ZeroizedBytes::new(data.clone());
        assert_eq!(zb.as_slice(), &data);
    }

    #[test]
    fn test_security_level_default() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::High);
    }

    #[test]
    fn test_performance_preference_default() {
        assert_eq!(PerformancePreference::default(), PerformancePreference::Balanced);
    }

    #[test]
    fn test_algorithm_selection_default() {
        let sel = AlgorithmSelection::default();
        assert_eq!(sel, AlgorithmSelection::SecurityLevel(SecurityLevel::High));
    }

    // Tests for CryptoConfig (stays in arc-core)

    #[test]
    fn test_crypto_config_new() {
        let config = CryptoConfig::new();
        assert!(!config.is_verified());
        assert!(config.get_session().is_none());
        assert_eq!(*config.get_selection(), AlgorithmSelection::SecurityLevel(SecurityLevel::High));
    }

    #[test]
    fn test_crypto_config_default() {
        let config = CryptoConfig::default();
        assert!(!config.is_verified());
    }

    #[test]
    fn test_crypto_config_use_case() {
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        assert_eq!(*config.get_selection(), AlgorithmSelection::UseCase(UseCase::SecureMessaging));
    }

    #[test]
    fn test_crypto_config_security_level() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
        assert_eq!(
            *config.get_selection(),
            AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum)
        );
    }

    #[test]
    fn test_crypto_config_validate_no_session() {
        let config = CryptoConfig::new();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_crypto_config_clone_debug() {
        let config = CryptoConfig::new().use_case(UseCase::Authentication);
        let cloned = config.clone();
        assert_eq!(cloned.get_selection(), config.get_selection());
        let debug = format!("{:?}", config);
        assert!(debug.contains("CryptoConfig"));
    }

    // --- ComplianceMode integration tests ---

    #[test]
    fn test_crypto_config_compliance_default() {
        let config = CryptoConfig::new();
        assert_eq!(*config.get_compliance(), ComplianceMode::Default);
    }

    #[test]
    fn test_crypto_config_compliance_builder() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_crypto_config_compliance_getter() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        assert_eq!(*config.get_compliance(), ComplianceMode::Cnsa2_0);
    }

    #[test]
    fn test_use_case_auto_compliance_government() {
        let config = CryptoConfig::new().use_case(UseCase::GovernmentClassified);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_healthcare() {
        let config = CryptoConfig::new().use_case(UseCase::HealthcareRecords);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_payment() {
        let config = CryptoConfig::new().use_case(UseCase::PaymentCard);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_financial() {
        let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_messaging_is_default() {
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        assert_eq!(*config.get_compliance(), ComplianceMode::Default);
    }

    #[test]
    fn test_use_case_auto_compliance_explicit_override() {
        // Explicitly setting compliance BEFORE use_case should preserve the explicit value
        let config = CryptoConfig::new()
            .compliance(ComplianceMode::Default)
            .use_case(UseCase::GovernmentClassified);
        assert_eq!(*config.get_compliance(), ComplianceMode::Default);
    }

    #[test]
    fn test_cnsa_requires_quantum() {
        // CNSA 2.0 with a non-Quantum security level should fail validation
        let config = CryptoConfig::new()
            .compliance(ComplianceMode::Cnsa2_0)
            .security_level(SecurityLevel::High);
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
        assert!(err_msg.contains("Quantum"));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_fips_compliance_without_feature() {
        // Without the fips feature, FIPS compliance should fail validation
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("fips"));
        assert!(err_msg.contains("Rebuild"));
    }

    // --- validate_scheme_compliance tests ---

    #[test]
    fn test_default_compliance_allows_all_schemes() {
        let config = CryptoConfig::new(); // Default compliance
        assert!(config.validate_scheme_compliance("aes-256-gcm").is_ok());
        assert!(config.validate_scheme_compliance("ed25519").is_ok());
        assert!(config.validate_scheme_compliance("ml-dsa-65").is_ok());
        assert!(config.validate_scheme_compliance("chacha20-poly1305").is_ok());
        assert!(config.validate_scheme_compliance("hybrid-ml-dsa-65-ed25519").is_ok());
    }

    #[test]
    fn test_fips_rejects_chacha() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        let result = config.validate_scheme_compliance("chacha20-poly1305");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("FIPS 140-3"));
        assert!(err_msg.contains("chacha"));
    }

    #[test]
    fn test_fips_allows_aes_gcm() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        assert!(config.validate_scheme_compliance("aes-256-gcm").is_ok());
    }

    #[test]
    fn test_fips_allows_pq_schemes() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        assert!(config.validate_scheme_compliance("ml-kem-768").is_ok());
        assert!(config.validate_scheme_compliance("ml-dsa-65").is_ok());
        assert!(config.validate_scheme_compliance("slh-dsa-shake-128s").is_ok());
        assert!(config.validate_scheme_compliance("hybrid-ml-dsa-65-ed25519").is_ok());
    }

    #[test]
    fn test_cnsa_rejects_ed25519() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        let result = config.validate_scheme_compliance("ed25519");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
        assert!(err_msg.contains("ed25519"));
    }

    #[test]
    fn test_cnsa_rejects_standalone_aes_gcm() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        let result = config.validate_scheme_compliance("aes-256-gcm");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
    }

    #[test]
    fn test_cnsa_allows_pq_schemes() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        assert!(config.validate_scheme_compliance("ml-kem-1024").is_ok());
        assert!(config.validate_scheme_compliance("ml-dsa-87").is_ok());
        assert!(config.validate_scheme_compliance("slh-dsa-shake-256s").is_ok());
        assert!(config.validate_scheme_compliance("fn-dsa").is_ok());
    }

    #[test]
    fn test_cnsa_allows_hybrid_schemes() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        assert!(config.validate_scheme_compliance("hybrid-ml-dsa-65-ed25519").is_ok());
        assert!(config.validate_scheme_compliance("hybrid-ml-kem-768-x25519-aes-256-gcm").is_ok());
    }

    // =========================================================================
    // Parameter Influence Tests (Audit 4.12)
    // =========================================================================

    #[test]
    fn test_force_scheme_builder_sets_selection() {
        let config = CryptoConfig::new().force_scheme(CryptoScheme::PostQuantum);
        assert_eq!(
            *config.get_selection(),
            AlgorithmSelection::ForcedScheme(CryptoScheme::PostQuantum)
        );
    }

    #[test]
    fn test_force_scheme_overrides_use_case() {
        let config = CryptoConfig::new()
            .use_case(UseCase::FileStorage)
            .force_scheme(CryptoScheme::Symmetric);
        // force_scheme should override the use case
        assert_eq!(
            *config.get_selection(),
            AlgorithmSelection::ForcedScheme(CryptoScheme::Symmetric)
        );
    }

    #[test]
    fn test_force_scheme_overrides_security_level() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .force_scheme(CryptoScheme::Hybrid);
        assert_eq!(*config.get_selection(), AlgorithmSelection::ForcedScheme(CryptoScheme::Hybrid));
    }
}
