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
}

impl<'a> Default for CryptoConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CryptoConfig<'a> {
    /// Creates new configuration with defaults (High security, no session).
    #[must_use]
    pub fn new() -> Self {
        Self { session: None, selection: AlgorithmSelection::default() }
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
    #[must_use]
    pub fn use_case(mut self, use_case: UseCase) -> Self {
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

    /// Returns true if a session is set (verified mode).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.session.is_some()
    }

    /// Validates the configuration.
    ///
    /// Checks session expiry if present.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SessionExpired` if the session has expired.
    pub fn validate(&self) -> crate::unified_api::error::Result<()> {
        if let Some(session) = self.session {
            session.verify_valid()?;
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
}
