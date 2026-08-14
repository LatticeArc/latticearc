//! Fundamental cryptographic types for LatticeArc Core.
//!
//! Most types are defined in [`crate::types::types`] and re-exported here.
//! `CryptoConfig<'a>` stays here because it references `VerifiedSession`
//! which depends on Ed25519 FFI.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

// Re-export all pure-Rust types from types module
pub use crate::types::secrets::{SecretBytes, SecretVec};
pub use crate::types::types::*;
// Re-export type-safe encryption types (EncryptKey, DecryptKey, EncryptionScheme, etc.)
pub use crate::unified_api::crypto_types::{
    DecryptKey, EncryptKey, EncryptedOutput, EncryptionScheme, HybridComponents,
};

use crate::unified_api::zero_trust::VerifiedSession;

/// Returns the default compliance mode for a given use case.
///
/// Regulated use cases automatically get FIPS 140-3 compliance,
/// which will be validated at operation time (failing gracefully
/// if the `fips` feature is not enabled).
fn default_compliance_for_use_case(use_case: UseCase) -> ComplianceMode {
    match use_case {
        // Regulated industries require FIPS 140-3 by default
        UseCase::GovernmentClassified
        | UseCase::HealthcareRecords
        | UseCase::PaymentCard
        | UseCase::FinancialTransactions => ComplianceMode::Fips140_3,
        // Non-regulated use cases — explicitly listed so new variants trigger
        // a compile error, forcing a conscious compliance decision.
        UseCase::SecureMessaging
        | UseCase::EmailEncryption
        | UseCase::VpnTunnel
        | UseCase::ApiSecurity
        | UseCase::FileStorage
        | UseCase::DatabaseEncryption
        | UseCase::CloudStorage
        | UseCase::BackupArchive
        | UseCase::ConfigSecrets
        | UseCase::Authentication
        | UseCase::SessionToken
        | UseCase::DigitalCertificate
        | UseCase::KeyExchange
        | UseCase::LegalDocuments
        | UseCase::BlockchainTransaction
        | UseCase::IoTDevice
        | UseCase::FirmwareSigning
        | UseCase::AuditLog => ComplianceMode::Default,
    }
}

// ============================================================================
// Unified Crypto Configuration (stays in unified_api due to VerifiedSession FFI dep)
// ============================================================================

/// Unified configuration for cryptographic operations.
///
/// Provides a single, consistent way to configure encrypt, decrypt, sign, and verify
/// operations. Uses a builder pattern for ergonomic configuration.
///
/// # Examples
///
/// ```rust,no_run
/// # use latticearc::unified_api::{encrypt, CryptoConfig, UseCase, SecurityLevel, VerifiedSession, generate_keypair, EncryptKey};
/// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
/// # let data = b"secret";
///
/// // Hybrid encryption (recommended - ML-KEM-768 + X25519 + AES-256-GCM)
/// let (pk, _sk) = latticearc::generate_hybrid_keypair()?;
/// encrypt(data, EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
///
/// // With Zero Trust session
/// # let (ed_pk, ed_sk) = generate_keypair()?;
/// let session = VerifiedSession::establish(ed_pk.as_slice(), ed_sk.expose_secret())?;
/// encrypt(data, EncryptKey::Hybrid(&pk),
///     CryptoConfig::new().session(&session))?;
///
/// // With use case (recommended - library picks optimal algorithm)
/// encrypt(data, EncryptKey::Hybrid(&pk), CryptoConfig::new()
///     .session(&session)
///     .use_case(UseCase::FileStorage))?;
///
/// // Symmetric encryption (AES-256-GCM). Generate a fresh key from the OS
/// // CSPRNG — `[0u8; 32]` is rejected as a weak key.
/// let key = latticearc::primitives::rand::random_bytes(32);
/// encrypt(data, EncryptKey::Symmetric(&key), CryptoConfig::new()
///     .force_scheme(latticearc::CryptoScheme::Symmetric))?;
///
/// // With FIPS compliance (requires `fips` feature)
/// use latticearc::types::types::ComplianceMode;
/// encrypt(data, EncryptKey::Hybrid(&pk), CryptoConfig::new()
///     .compliance(ComplianceMode::Fips140_3))?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CryptoConfig<'a> {
    /// Optional Zero Trust verified session.
    /// If None, operates in unverified mode.
    ///
    /// Consumer: `CryptoConfig::validate()` (session expiry gate, called at
    /// the top of every unified-API operation).
    session: Option<&'a VerifiedSession>,
    /// Algorithm selection mode (use case or security level).
    ///
    /// Consumer: `convenience::api::{select_encryption_scheme, select_signature_scheme}`
    /// via `get_selection()`.
    selection: AlgorithmSelection,
    /// Compliance mode for regulatory requirements.
    ///
    /// Consumer: `CryptoConfig::validate_scheme_compliance()` via `get_compliance()`.
    compliance: ComplianceMode,
    /// Whether the user explicitly set compliance (vs. auto-set by use_case).
    ///
    /// Consumer: `CryptoConfig::validate_scheme_compliance()` (explicit
    /// compliance is enforced; use-case-derived compliance is advisory).
    compliance_explicit: bool,
    /// Whether the user explicitly pinned a `SecurityLevel` (vs. left it
    /// at the constructor default). Only when this is true does
    /// `validate_scheme_compliance` enforce a minimum-strength gate
    /// against the configured level — otherwise the existing scheme-
    /// dispatch path (which routes by string name) decides what's
    /// acceptable. Without this discrimination a defaulted-to-High
    /// config would reject every ml-dsa-44 / ml-kem-512 caller.
    security_level_explicit: bool,
    /// Cryptographic mode: hybrid (default) or PQ-only.
    ///
    /// Consumer: `convenience::api` dispatch arms via `get_crypto_mode()`
    /// (routes to the PQ-only scheme table when `CryptoMode::PqOnly`).
    crypto_mode: CryptoMode,
    /// Optional maximum age (seconds) for `EncryptedOutput.timestamp` on
    /// decrypt. `None` (default) skips the check; `Some(n)` rejects any
    /// ciphertext whose stamped timestamp is more than `n` seconds older
    /// than the current wall-clock. See [`max_age`](Self::max_age).
    ///
    /// Consumer: `convenience::api::decrypt_with_aad()` replay-window guard
    /// (surfaces as `CoreError::Replay`).
    max_age_seconds: Option<u64>,
}

impl<'a> Default for CryptoConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CryptoConfig<'a> {
    /// Creates new configuration with defaults (High security, hybrid mode, no session, no compliance restrictions).
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: None,
            selection: AlgorithmSelection::default(),
            compliance: ComplianceMode::Default,
            compliance_explicit: false,
            security_level_explicit: false,
            crypto_mode: CryptoMode::Hybrid,
            max_age_seconds: None,
        }
    }

    /// Reject ciphertexts whose stamped `timestamp` is older than `seconds`.
    ///
    /// Defence-in-depth replay protection at the convenience-API layer.
    /// `EncryptedOutput.timestamp` is set on encrypt to the current
    /// `Utc::now().timestamp()` (seconds since epoch); when this option
    /// is set, [`decrypt`](crate::unified_api::convenience::api::decrypt)
    /// rejects ciphertexts whose timestamp is more than `seconds` behind
    /// the receiver's wall-clock as
    /// `CoreError::Replay { age_seconds, max_age_seconds }`.
    ///
    /// The dedicated `Replay` variant — not `ResourceExceeded` — is
    /// deliberate: a caller can pattern-match a suspected replay and raise an
    /// alert, distinct from a genuine size-quota rejection.
    ///
    /// # Caveats
    ///
    /// - **Wall-clock based.** Receivers with skewed clocks will reject
    ///   freshly-encrypted ciphertexts; senders racing the receiver's
    ///   clock will see false rejections. Pair with NTP discipline on
    ///   both ends, and pick `seconds` large enough to swallow expected
    ///   skew (typically 60s — 5min).
    /// - **NOT a substitute for monotonic counter / nonce-cache replay
    ///   protection** at the protocol layer. An attacker replaying a
    ///   ciphertext WITHIN the `max_age` window still succeeds. This
    ///   guard bounds the replay window; it does not eliminate it.
    ///   Applications that need exactly-once delivery must layer their
    ///   own replay-cache on top.
    /// - **No-op when unset.** Default is `None` to preserve backward
    ///   compatibility with callers who use the timestamp purely for
    ///   audit / display.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = Some(seconds);
        self
    }

    /// Returns the configured replay-protection window, in seconds.
    #[must_use]
    pub fn max_age_seconds(&self) -> Option<u64> {
        self.max_age_seconds
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
            self.compliance = default_compliance_for_use_case(use_case);
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
        self.security_level_explicit = true;
        self
    }

    /// Sets the cryptographic mode (hybrid or PQ-only).
    ///
    /// - `CryptoMode::Hybrid` (default): PQ + classical algorithms for defense-in-depth
    /// - `CryptoMode::PqOnly`: Pure post-quantum, no classical component
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use latticearc::unified_api::{CryptoConfig, encrypt, EncryptKey};
    /// # use latticearc::types::types::CryptoMode;
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// let (pk, _sk) = latticearc::hybrid::pq_only::generate_pq_keypair()
    ///     .map_err(|e| latticearc::unified_api::error::CoreError::InvalidInput(e.to_string()))?;
    /// encrypt(b"data", EncryptKey::PqOnly(&pk), CryptoConfig::new()
    ///     .crypto_mode(CryptoMode::PqOnly))?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn crypto_mode(mut self, mode: CryptoMode) -> Self {
        self.crypto_mode = mode;
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
    /// # use latticearc::unified_api::{CryptoConfig, encrypt, EncryptKey};
    /// # use latticearc::types::types::CryptoScheme;
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// // Generate a fresh 256-bit key — `[0u8; 32]` fails the weak-key check.
    /// let key = latticearc::primitives::rand::random_bytes(32);
    /// // Force symmetric encryption
    /// encrypt(b"data", EncryptKey::Symmetric(&key), CryptoConfig::new()
    ///     .force_scheme(CryptoScheme::Symmetric))?;
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
    /// # use latticearc::unified_api::{CryptoConfig, encrypt, EncryptKey};
    /// # use latticearc::types::types::ComplianceMode;
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// let (pk, _sk) = latticearc::generate_hybrid_keypair()?;
    /// // Explicitly require FIPS compliance
    /// encrypt(b"data", EncryptKey::Hybrid(&pk), CryptoConfig::new()
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

    /// Returns the cryptographic mode (hybrid or PQ-only).
    #[must_use]
    pub fn get_crypto_mode(&self) -> CryptoMode {
        self.crypto_mode
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

        /// Schemes explicitly banned under FIPS 140-3.
        const FIPS_BANNED: &[&str] = &["chacha20-poly1305"];

        /// Pure classical schemes banned under CNSA 2.0.
        /// Hybrid schemes containing these as a component are allowed
        /// (transitional per NIST SP 800-227).
        const CNSA_BANNED_CLASSICAL: &[&str] = &["ed25519", "aes-256-gcm"];

        match self.compliance {
            ComplianceMode::Default => {}
            ComplianceMode::Fips140_3 => {
                if FIPS_BANNED.contains(&scheme) {
                    return Err(CoreError::ComplianceViolation(format!(
                        "Scheme '{scheme}' is not FIPS 140-3 approved. \
                         Use AES-256-GCM or a FIPS-validated algorithm.",
                    )));
                }
            }
            ComplianceMode::Cnsa2_0 => {
                // Only reject exact matches — hybrid schemes that embed a
                // classical component (e.g. "hybrid-ml-dsa-65-ed25519") are
                // allowed as transitional per NIST SP 800-227.
                if CNSA_BANNED_CLASSICAL.contains(&scheme) {
                    return Err(CoreError::ComplianceViolation(format!(
                        "Scheme '{scheme}' is not permitted under CNSA 2.0 (post-quantum required). \
                         Use ML-KEM, ML-DSA, SLH-DSA, FN-DSA, or a hybrid scheme.",
                    )));
                }
            }
        }

        // SECURITY: also gate on the configured `SecurityLevel`. Without
        // this check, a server with `SecurityLevel::Maximum` would
        // silently accept a wire-supplied `hybrid-ml-kem-512-…` scheme
        // (NIST Level 1) if an attacker also supplied a valid 512-bit
        // ciphertext. The compliance allowlist alone is not sufficient
        // — `hybrid-ml-kem-512-aes-256-gcm` passes both FIPS and CNSA
        // bans yet is below `Maximum`.
        //
        // Only enforced when the caller EXPLICITLY pinned a level via
        // `.security_level(...)` — not when the constructor default
        // `SecurityLevel::High` is in play. Without this distinction every
        // ml-dsa-44 / ml-kem-512 caller using `CryptoConfig::new()` would
        // be rejected, which contradicts the Standard-tier APIs being a
        // first-class entry point. UseCase-driven and forced-scheme
        // selections already constrain the scheme via dispatch.
        //
        // `None` from `scheme_min_security_level` means we don't recognise
        // the scheme — let the caller's dispatch path return the canonical
        // "unknown scheme" error.
        if self.security_level_explicit
            && let AlgorithmSelection::SecurityLevel(configured_level) = self.selection
            && let Some(scheme_level) = scheme_min_security_level(scheme)
            && (scheme_level as u8) < (configured_level as u8)
        {
            return Err(CoreError::ComplianceViolation(format!(
                "Scheme '{scheme}' provides {scheme_level:?} security but \
                 CryptoConfig requires at least {configured_level:?}. \
                 Either downgrade the SecurityLevel via .security_level() \
                 or provide a stronger scheme."
            )));
        }
        Ok(())
    }
}

/// Map a scheme tag string to the minimum `SecurityLevel` it provides.
///
/// Returns `None` for schemes this build doesn't recognise; callers
/// should treat that as "let the dispatch layer reject as unknown"
/// rather than as "any level is fine."
fn scheme_min_security_level(scheme: &str) -> Option<SecurityLevel> {
    // NIST PQC categories map to SecurityLevel as:
    //   Category 1 (128-bit) → Standard (ML-KEM-512, ML-DSA-44, SLH-DSA-128*)
    //   Category 3 (192-bit) → High     (ML-KEM-768, ML-DSA-65, SLH-DSA-192*)
    //   Category 5 (256-bit) → Maximum  (ML-KEM-1024, ML-DSA-87, SLH-DSA-256*)
    // Hybrid schemes inherit the level of their PQ component (the
    // classical sidecar contributes zero PQ security).
    //
    // the previous shape used
    // `s.contains("128")`/`"192"`/`"256"` substring matching, which
    // accepted any future scheme name containing those literals
    // (e.g. `sha-256`, `slh-dsa-shake-256s`, hypothetical
    // `prefix-256xxx`) as a security-level claim regardless of actual
    // algorithm strength. Substring matching across security-tier
    // dispatch is a correctness footgun.
    //
    // The needles below are therefore full algorithm names
    // (`ml-kem-512`), never bare size literals (`512`). A composite
    // scheme tag embeds its PQ algorithm name verbatim in every
    // spelling the library emits or accepts —
    // `pq-ml-kem-512-aes-256-gcm`, `hybrid-ml-kem-512-aes-256-gcm`,
    // `hybrid-ml-dsa-44-ed25519`, `ml-dsa-44-hybrid-ed25519` — so
    // substring containment on the *algorithm name* classifies all of
    // them without reintroducing the size-literal footgun.
    //
    // Matching must NOT be restricted to a prefix (`starts_with
    // ("hybrid-")`) or to `-`-delimited whole tokens: the PQ algorithm
    // name is itself hyphenated, so token equality never matches, and
    // the `pq-` prefixed and `-hybrid-ed25519` suffixed forms carry no
    // `hybrid-` prefix. Either restriction silently returns `None` for
    // real wire schemes, which disables the minimum-strength gate in
    // `validate_scheme_compliance` for exactly those spellings.
    let s = scheme.to_ascii_lowercase();

    // Only the SLH-DSA `-shake-*s` (small) variants are exposed by
    // `SlhDsaSecurityLevel`; `-shake-*f` (fast) and `-sha2-*` are not
    // wired through and would never reach here from a real keygen path.

    // Standard (Category 1 / 128-bit PQ)
    if matches!(
        s.as_str(),
        "ml-kem-512"
            | "ml-dsa-44"
            | "slh-dsa-shake-128s"
            | "fn-dsa-512"
            | "ed25519"
            | "aes-256-gcm"
            | "chacha20-poly1305"
    ) || s.contains("ml-kem-512")
        || s.contains("ml-dsa-44")
    {
        Some(SecurityLevel::Standard)
    } else if matches!(s.as_str(), "ml-kem-768" | "ml-dsa-65" | "slh-dsa-shake-192s")
        || s.contains("ml-kem-768")
        || s.contains("ml-dsa-65")
    {
        Some(SecurityLevel::High)
    } else if matches!(
        s.as_str(),
        "ml-kem-1024" | "ml-dsa-87" | "slh-dsa-shake-256s" | "fn-dsa-1024"
    ) || s.contains("ml-kem-1024")
        || s.contains("ml-dsa-87")
    {
        Some(SecurityLevel::Maximum)
    } else {
        None
    }
}

impl<'a> CryptoConfig<'a> {
    /// Validates the configuration.
    ///
    /// Checks:
    /// 1. Session expiry (if present)
    /// 2. FIPS feature availability (if compliance mode requires it)
    /// 3. CNSA 2.0 requires `CryptoMode::PqOnly`
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SessionExpired` if the session has expired.
    /// Returns `CoreError::FeatureNotAvailable` if compliance mode requires FIPS
    /// but the `fips` feature is not enabled.
    /// Returns `CoreError::ConfigurationError` if CNSA 2.0 is set but the crypto
    /// mode is not `PqOnly`.
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
                 Rebuild with: latticearc = {{ features = [\"fips\"] }}",
                self.compliance
            )));
        }

        // 3. CNSA 2.0 requires CryptoMode::PqOnly
        if matches!(self.compliance, ComplianceMode::Cnsa2_0)
            && !matches!(self.crypto_mode, CryptoMode::PqOnly)
        {
            return Err(CoreError::ConfigurationError(
                "CNSA 2.0 compliance requires CryptoMode::PqOnly. \
                 Use .crypto_mode(CryptoMode::PqOnly) on your CryptoConfig."
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test/bench scaffolding: lints suppressed for this module")]
mod tests {
    use super::*;

    // Tests for types that moved to types module

    #[test]
    fn test_security_level_default_is_standard_succeeds() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::High);
    }

    #[test]
    fn test_performance_preference_default_is_balanced_succeeds() {
        assert_eq!(PerformancePreference::default(), PerformancePreference::Balanced);
    }

    #[test]
    fn test_algorithm_selection_default_is_automatic_succeeds() {
        let sel = AlgorithmSelection::default();
        assert_eq!(sel, AlgorithmSelection::SecurityLevel(SecurityLevel::High));
    }

    // Tests for CryptoConfig (stays in unified_api)

    #[test]
    fn test_crypto_config_new_sets_fields_succeeds() {
        let config = CryptoConfig::new();
        assert!(!config.is_verified());
        assert!(config.get_session().is_none());
        assert_eq!(*config.get_selection(), AlgorithmSelection::SecurityLevel(SecurityLevel::High));
        assert_eq!(config.get_crypto_mode(), CryptoMode::Hybrid);
    }

    #[test]
    fn test_crypto_config_crypto_mode_builder_sets_pq_only() {
        let config = CryptoConfig::new().crypto_mode(CryptoMode::PqOnly);
        assert_eq!(config.get_crypto_mode(), CryptoMode::PqOnly);
    }

    #[test]
    fn test_crypto_config_crypto_mode_default_is_hybrid() {
        assert_eq!(CryptoConfig::new().get_crypto_mode(), CryptoMode::Hybrid);
    }

    #[test]
    fn test_crypto_config_default_sets_expected_fields_succeeds() {
        let config = CryptoConfig::default();
        assert!(!config.is_verified());
    }

    #[test]
    fn test_crypto_config_use_case_sets_use_case_field_succeeds() {
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        assert_eq!(*config.get_selection(), AlgorithmSelection::UseCase(UseCase::SecureMessaging));
    }

    #[test]
    fn test_crypto_config_security_level_sets_security_field_succeeds() {
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
        assert_eq!(
            *config.get_selection(),
            AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum)
        );
    }

    #[test]
    fn test_crypto_config_validate_no_session_succeeds() {
        let config = CryptoConfig::new();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_crypto_config_clone_debug_work_correctly_succeeds() {
        let config = CryptoConfig::new().use_case(UseCase::Authentication);
        let cloned = config.clone();
        assert_eq!(cloned.get_selection(), config.get_selection());
        let debug = format!("{:?}", config);
        assert!(debug.contains("CryptoConfig"));
    }

    // --- ComplianceMode integration tests ---

    #[test]
    fn test_crypto_config_compliance_default_is_standard_succeeds() {
        let config = CryptoConfig::new();
        assert_eq!(*config.get_compliance(), ComplianceMode::Default);
    }

    #[test]
    fn test_crypto_config_compliance_builder_sets_compliance_field_succeeds() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_crypto_config_compliance_getter_returns_compliance_field_succeeds() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        assert_eq!(*config.get_compliance(), ComplianceMode::Cnsa2_0);
    }

    #[test]
    fn test_use_case_auto_compliance_government_is_correct() {
        let config = CryptoConfig::new().use_case(UseCase::GovernmentClassified);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_healthcare_is_correct() {
        let config = CryptoConfig::new().use_case(UseCase::HealthcareRecords);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_payment_is_correct() {
        let config = CryptoConfig::new().use_case(UseCase::PaymentCard);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_financial_is_correct() {
        let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
        assert_eq!(*config.get_compliance(), ComplianceMode::Fips140_3);
    }

    #[test]
    fn test_use_case_auto_compliance_messaging_is_default() {
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        assert_eq!(*config.get_compliance(), ComplianceMode::Default);
    }

    #[test]
    fn test_use_case_auto_compliance_explicit_override_is_correct() {
        // Explicitly setting compliance BEFORE use_case should preserve the explicit value
        let config = CryptoConfig::new()
            .compliance(ComplianceMode::Default)
            .use_case(UseCase::GovernmentClassified);
        assert_eq!(*config.get_compliance(), ComplianceMode::Default);
    }

    // CNSA 2.0 implies the `fips` feature (`compliance.requires_fips()` returns
    // true, so validate() short-circuits on the FIPS-availability check before
    // ever reaching the CNSA + non-PqOnly branch). The PqOnly enforcement is
    // therefore only observable in `fips`-enabled builds.
    #[cfg(feature = "fips")]
    #[test]
    fn test_cnsa_requires_pq_only_mode_is_correct() {
        // CNSA 2.0 with Hybrid mode should fail validation
        let config = CryptoConfig::new()
            .compliance(ComplianceMode::Cnsa2_0)
            .security_level(SecurityLevel::High);
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
        assert!(err_msg.contains("PqOnly"));
    }

    #[test]
    fn test_cnsa_with_pq_only_mode_passes_validation() {
        // CNSA 2.0 with PqOnly mode should pass (ignoring fips feature check)
        let config = CryptoConfig::new()
            .compliance(ComplianceMode::Cnsa2_0)
            .crypto_mode(CryptoMode::PqOnly)
            .security_level(SecurityLevel::Maximum);
        // On non-fips builds this will fail on FIPS check, not CNSA check
        let result = config.validate();
        if cfg!(feature = "fips") {
            assert!(result.is_ok());
        } else {
            // Should fail on FIPS availability, not on CNSA mode check
            let err_msg = format!("{}", result.unwrap_err());
            assert!(err_msg.contains("fips"));
        }
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_fips_compliance_without_feature_is_correct() {
        // Without the fips feature, FIPS compliance should fail validation
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("fips"));
        assert!(err_msg.contains("Rebuild"));
    }

    // --- validate_scheme_compliance tests ---

    /// Every scheme spelling the library can emit or accept on the wire must
    /// be classifiable by `scheme_min_security_level`. A `None` here silently
    /// disables the minimum-strength gate for that spelling, which is exactly
    /// how the `pq-`-prefixed and `-hybrid-ed25519`-suffixed forms escaped it.
    #[test]
    fn test_every_wire_scheme_spelling_is_level_classified_succeeds() {
        // `pq-` prefixed encryption tags (crypto_types::EncryptionScheme).
        // Signature tags, canonical hybrid and legacy alias spellings
        // (types::domains + api.rs dispatch).
        let level_1 = [
            "pq-ml-kem-512-aes-256-gcm",
            "hybrid-ml-kem-512-aes-256-gcm",
            "pq-ml-dsa-44",
            "hybrid-ml-dsa-44-ed25519",
            "ml-dsa-44-hybrid-ed25519",
        ];
        let level_3 = [
            "pq-ml-kem-768-aes-256-gcm",
            "hybrid-ml-kem-768-aes-256-gcm",
            "pq-ml-dsa-65",
            "hybrid-ml-dsa-65-ed25519",
            "ml-dsa-65-hybrid-ed25519",
        ];
        let level_5 = [
            "pq-ml-kem-1024-aes-256-gcm",
            "hybrid-ml-kem-1024-aes-256-gcm",
            "pq-ml-dsa-87",
            "hybrid-ml-dsa-87-ed25519",
            "ml-dsa-87-hybrid-ed25519",
        ];

        for scheme in level_1 {
            assert_eq!(
                scheme_min_security_level(scheme),
                Some(SecurityLevel::Standard),
                "{scheme} must classify as Standard"
            );
        }
        for scheme in level_3 {
            assert_eq!(
                scheme_min_security_level(scheme),
                Some(SecurityLevel::High),
                "{scheme} must classify as High"
            );
        }
        for scheme in level_5 {
            assert_eq!(
                scheme_min_security_level(scheme),
                Some(SecurityLevel::Maximum),
                "{scheme} must classify as Maximum"
            );
        }
    }

    /// The gate must fire on the `pq-`/alias spellings, not just on the
    /// `hybrid-` prefixed ones. Wire-supplied schemes reach this check from
    /// `decrypt` and `verify`, so a spelling that skips it lets a Category-1
    /// scheme through a `SecurityLevel::Maximum` configuration.
    #[test]
    fn test_below_minimum_level_rejected_for_all_spellings_fails() {
        for scheme in [
            "pq-ml-kem-512-aes-256-gcm",
            "hybrid-ml-kem-512-aes-256-gcm",
            "pq-ml-dsa-44",
            "ml-dsa-44-hybrid-ed25519",
            "hybrid-ml-dsa-44-ed25519",
        ] {
            let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
            let result = config.validate_scheme_compliance(scheme);
            assert!(result.is_err(), "{scheme} must be rejected under Maximum");
            let err_msg = format!("{}", result.unwrap_err());
            assert!(err_msg.contains("Standard"), "{scheme}: {err_msg}");
            assert!(err_msg.contains("Maximum"), "{scheme}: {err_msg}");
        }
    }

    /// A scheme at or above the configured minimum must still pass — the gate
    /// rejects on strength, not on spelling.
    #[test]
    fn test_at_or_above_minimum_level_accepted_for_all_spellings_succeeds() {
        for scheme in ["pq-ml-kem-1024-aes-256-gcm", "ml-dsa-87-hybrid-ed25519"] {
            let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
            assert!(
                config.validate_scheme_compliance(scheme).is_ok(),
                "{scheme} must pass under Maximum"
            );
        }
        for scheme in ["pq-ml-kem-768-aes-256-gcm", "ml-dsa-65-hybrid-ed25519"] {
            let config = CryptoConfig::new().security_level(SecurityLevel::High);
            assert!(
                config.validate_scheme_compliance(scheme).is_ok(),
                "{scheme} must pass under High"
            );
        }
    }

    /// The classifier must not treat an embedded key-size or hash-size literal
    /// as a strength claim — this is the footgun the token-boundary rewrite was
    /// introduced to close, and the `contains` form must not reopen it.
    #[test]
    fn test_unrelated_size_literals_are_not_level_claims_is_correct() {
        for scheme in ["sha-256", "slh-dsa-sha2-128f", "hmac-sha-512", "prefix-1024-suffix"] {
            assert_eq!(
                scheme_min_security_level(scheme),
                None,
                "{scheme} must not be classified from an embedded size literal"
            );
        }
    }

    #[test]
    fn test_default_compliance_allows_all_schemes_is_correct() {
        let config = CryptoConfig::new(); // Default compliance
        assert!(config.validate_scheme_compliance("aes-256-gcm").is_ok());
        assert!(config.validate_scheme_compliance("ed25519").is_ok());
        assert!(config.validate_scheme_compliance("ml-dsa-65").is_ok());
        assert!(config.validate_scheme_compliance("chacha20-poly1305").is_ok());
        assert!(config.validate_scheme_compliance("hybrid-ml-dsa-65-ed25519").is_ok());
    }

    #[test]
    fn test_fips_rejects_chacha_fails() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        let result = config.validate_scheme_compliance("chacha20-poly1305");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("FIPS 140-3"));
        assert!(err_msg.contains("chacha"));
    }

    #[test]
    fn test_fips_allows_aes_gcm_succeeds() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        assert!(config.validate_scheme_compliance("aes-256-gcm").is_ok());
    }

    #[test]
    fn test_fips_allows_pq_schemes_succeeds() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Fips140_3);
        assert!(config.validate_scheme_compliance("ml-kem-768").is_ok());
        assert!(config.validate_scheme_compliance("ml-dsa-65").is_ok());
        assert!(config.validate_scheme_compliance("slh-dsa-shake-128s").is_ok());
        assert!(config.validate_scheme_compliance("hybrid-ml-dsa-65-ed25519").is_ok());
    }

    #[test]
    fn test_cnsa_rejects_ed25519_fails() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        let result = config.validate_scheme_compliance("ed25519");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
        assert!(err_msg.contains("ed25519"));
    }

    #[test]
    fn test_cnsa_rejects_standalone_aes_gcm_fails() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        let result = config.validate_scheme_compliance("aes-256-gcm");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
    }

    #[test]
    fn test_cnsa_allows_pq_schemes_succeeds() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        assert!(config.validate_scheme_compliance("ml-kem-1024").is_ok());
        assert!(config.validate_scheme_compliance("ml-dsa-87").is_ok());
        assert!(config.validate_scheme_compliance("slh-dsa-shake-256s").is_ok());
        assert!(config.validate_scheme_compliance("fn-dsa").is_ok());
    }

    #[test]
    fn test_cnsa_allows_hybrid_schemes_succeeds() {
        let config = CryptoConfig::new().compliance(ComplianceMode::Cnsa2_0);
        assert!(config.validate_scheme_compliance("hybrid-ml-dsa-65-ed25519").is_ok());
        assert!(config.validate_scheme_compliance("hybrid-ml-kem-768-x25519-aes-256-gcm").is_ok());
    }

    // =========================================================================
    // Parameter Influence Tests (Audit 4.12)
    // =========================================================================

    #[test]
    fn test_force_scheme_builder_sets_selection_succeeds() {
        let config = CryptoConfig::new().force_scheme(CryptoScheme::PostQuantum);
        assert_eq!(
            *config.get_selection(),
            AlgorithmSelection::ForcedScheme(CryptoScheme::PostQuantum)
        );
    }

    #[test]
    fn test_force_scheme_overrides_use_case_is_correct() {
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
    fn test_force_scheme_overrides_security_level_is_correct() {
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .force_scheme(CryptoScheme::Hybrid);
        assert_eq!(*config.get_selection(), AlgorithmSelection::ForcedScheme(CryptoScheme::Hybrid));
    }
}
