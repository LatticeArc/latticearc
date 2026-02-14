#![deny(unsafe_code)]
#![deny(missing_docs)]

//! TLS security invariants for formal verification.
//!
//! This module defines and checks security properties that must hold throughout
//! the TLS connection lifecycle. These invariants are checked at construction
//! time and during state transitions.

use crate::{TlsConfig, TlsMode};

/// TLS security invariant checker.
///
/// Validates that TLS configurations and state transitions uphold
/// security invariants required for correct operation.
pub struct TlsInvariants {
    /// Require PQ-safe key exchange
    require_pq: bool,
    /// Minimum allowed TLS version (as u16)
    min_tls_version: u16,
    /// Require forward secrecy
    require_forward_secrecy: bool,
}

/// Result of invariant checking
#[derive(Debug, Clone)]
pub struct InvariantResult {
    /// Whether all invariants passed
    pub passed: bool,
    /// List of invariant violations (empty if passed)
    pub violations: Vec<String>,
}

impl TlsInvariants {
    /// Creates a new invariant checker with default security requirements.
    ///
    /// Defaults:
    /// - PQ not required (hybrid recommended but not enforced)
    /// - Minimum TLS 1.3 (0x0304)
    /// - Forward secrecy required
    #[must_use]
    pub fn new() -> Self {
        Self {
            require_pq: false,
            min_tls_version: 0x0304, // TLS 1.3
            require_forward_secrecy: true,
        }
    }

    /// Create strict invariants requiring PQ-safe key exchange.
    #[must_use]
    pub fn strict() -> Self {
        Self { require_pq: true, min_tls_version: 0x0304, require_forward_secrecy: true }
    }

    /// Set whether PQ key exchange is required.
    #[must_use]
    pub fn with_pq_required(mut self, required: bool) -> Self {
        self.require_pq = required;
        self
    }

    /// Set minimum TLS version.
    #[must_use]
    pub fn with_min_tls_version(mut self, version: u16) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Check all invariants against a TLS configuration.
    #[must_use]
    pub fn check(&self, config: &TlsConfig) -> InvariantResult {
        let mut violations = Vec::new();

        // INV-1: Mode must be PQ-safe if required
        if self.require_pq && config.mode == TlsMode::Classic {
            violations
                .push("INV-1: PQ key exchange required but Classic mode selected".to_string());
        }

        // INV-2: TLS version must meet minimum
        if let Some(min_ver) = config.min_protocol_version {
            let ver_num: u16 = min_ver.into();
            if ver_num < self.min_tls_version {
                violations.push(format!(
                    "INV-2: Minimum TLS version 0x{:04x} is below required 0x{:04x}",
                    ver_num, self.min_tls_version
                ));
            }
        }

        // INV-3: Forward secrecy - all TLS 1.3 modes use ephemeral keys
        // TLS 1.3 inherently provides forward secrecy, so this only checks
        // if TLS 1.2 is allowed (which may use static key exchange)
        if self.require_forward_secrecy
            && let Some(min_ver) = config.min_protocol_version
        {
            let ver_num: u16 = min_ver.into();
            if ver_num < 0x0303 {
                violations.push("INV-3: Forward secrecy requires TLS 1.2+ minimum".to_string());
            }
        }

        // INV-4: Key logging must not be enabled in strict mode
        if self.require_pq && config.enable_key_logging {
            violations
                .push("INV-4: Key logging enabled with strict security requirements".to_string());
        }

        InvariantResult { passed: violations.is_empty(), violations }
    }
}

impl Default for TlsInvariants {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn test_default_invariants_pass_default_config() {
        let inv = TlsInvariants::new();
        let config = TlsConfig::new();
        let result = inv.check(&config);
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_strict_invariants_fail_classic_mode() {
        let inv = TlsInvariants::strict();
        let config = TlsConfig { mode: TlsMode::Classic, ..TlsConfig::default() };
        let result = inv.check(&config);
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| v.contains("INV-1")));
    }

    #[test]
    fn test_strict_invariants_pass_hybrid_mode() {
        let inv = TlsInvariants::strict();
        let config = TlsConfig::new(); // default is Hybrid
        let result = inv.check(&config);
        assert!(result.passed);
    }

    #[test]
    fn test_strict_invariants_fail_key_logging() {
        let inv = TlsInvariants::strict();
        let config = TlsConfig::new().with_key_logging();
        let result = inv.check(&config);
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| v.contains("INV-4")));
    }

    #[test]
    fn test_custom_min_version() {
        let inv = TlsInvariants::new().with_min_tls_version(0x0304);
        let mut config = TlsConfig::new();
        config.min_protocol_version = Some(rustls::ProtocolVersion::TLSv1_2);
        let result = inv.check(&config);
        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| v.contains("INV-2")));
    }

    #[test]
    fn test_pq_required_builder() {
        let inv = TlsInvariants::new().with_pq_required(true);
        let config = TlsConfig { mode: TlsMode::Classic, ..TlsConfig::default() };
        let result = inv.check(&config);
        assert!(!result.passed);
    }

    #[test]
    fn test_invariant_result_debug() {
        let result = InvariantResult { passed: true, violations: vec![] };
        let debug = format!("{:?}", result);
        assert!(debug.contains("passed: true"));
    }
}
