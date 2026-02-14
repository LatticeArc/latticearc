#![deny(unsafe_code)]
#![deny(missing_docs)]

//! TLS security property definitions and verification.
//!
//! Defines the core security properties that a TLS implementation must guarantee:
//! - **Confidentiality**: Data encrypted in transit
//! - **Authentication**: Server (and optionally client) identity verified
//! - **Forward secrecy**: Past sessions protected even if long-term keys compromised
//! - **Integrity**: Data not modified in transit
//! - **PQ resistance**: Quantum-safe key exchange (when hybrid/PQ mode enabled)

use crate::{ClientVerificationMode, TlsConfig, TlsMode};

/// A verifiable security property of a TLS configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProperty {
    /// Data is encrypted during transit using authenticated encryption (AES-GCM or ChaCha20-Poly1305).
    Confidentiality,
    /// Server identity is verified via X.509 certificate chain.
    ServerAuthentication,
    /// Client identity is verified via mTLS.
    ClientAuthentication,
    /// Ephemeral key exchange protects past sessions from future key compromise.
    ForwardSecrecy,
    /// AEAD ciphers provide integrity guarantees on all application data.
    Integrity,
    /// Key exchange is resistant to quantum computing attacks.
    QuantumResistance,
}

/// Result of checking a single security property.
#[derive(Debug, Clone)]
pub struct PropertyCheck {
    /// The property being checked.
    pub property: SecurityProperty,
    /// Whether the property is satisfied.
    pub satisfied: bool,
    /// Explanation of the check result.
    pub reason: String,
}

/// Security property checker for TLS configurations.
pub struct SecurityProperties {
    /// Properties to check.
    required: Vec<SecurityProperty>,
}

impl SecurityProperties {
    /// Create a checker for the standard TLS security properties.
    ///
    /// Standard checks: Confidentiality, ServerAuthentication, ForwardSecrecy, Integrity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            required: vec![
                SecurityProperty::Confidentiality,
                SecurityProperty::ServerAuthentication,
                SecurityProperty::ForwardSecrecy,
                SecurityProperty::Integrity,
            ],
        }
    }

    /// Create a checker requiring all security properties including PQ resistance.
    #[must_use]
    pub fn full() -> Self {
        Self {
            required: vec![
                SecurityProperty::Confidentiality,
                SecurityProperty::ServerAuthentication,
                SecurityProperty::ClientAuthentication,
                SecurityProperty::ForwardSecrecy,
                SecurityProperty::Integrity,
                SecurityProperty::QuantumResistance,
            ],
        }
    }

    /// Add a required property.
    #[must_use]
    pub fn require(mut self, property: SecurityProperty) -> Self {
        if !self.required.contains(&property) {
            self.required.push(property);
        }
        self
    }

    /// Check all required properties against a TLS configuration.
    #[must_use]
    pub fn verify(&self, config: &TlsConfig) -> Vec<PropertyCheck> {
        self.required.iter().map(|prop| self.check_property(*prop, config)).collect()
    }

    /// Check whether all required properties are satisfied.
    #[must_use]
    pub fn all_satisfied(&self, config: &TlsConfig) -> bool {
        self.verify(config).iter().all(|c| c.satisfied)
    }

    #[allow(clippy::unused_self)] // Method on struct for API consistency
    fn check_property(&self, property: SecurityProperty, config: &TlsConfig) -> PropertyCheck {
        match property {
            SecurityProperty::Confidentiality => PropertyCheck {
                property,
                satisfied: true, // TLS 1.3 always uses AEAD
                reason: "TLS 1.3 mandates authenticated encryption (AES-GCM/ChaCha20-Poly1305)"
                    .to_string(),
            },
            SecurityProperty::ServerAuthentication => PropertyCheck {
                property,
                satisfied: true, // rustls always verifies server certificates
                reason: "rustls verifies server certificate chain against system root store"
                    .to_string(),
            },
            SecurityProperty::ClientAuthentication => {
                let satisfied = config.client_verification != ClientVerificationMode::None;
                PropertyCheck {
                    property,
                    satisfied,
                    reason: if satisfied {
                        format!("Client verification mode: {:?}", config.client_verification)
                    } else {
                        "Client authentication not configured (mTLS disabled)".to_string()
                    },
                }
            }
            SecurityProperty::ForwardSecrecy => PropertyCheck {
                property,
                satisfied: true, // TLS 1.3 mandates ephemeral key exchange
                reason: "TLS 1.3 uses ephemeral key exchange (X25519/ML-KEM) for all sessions"
                    .to_string(),
            },
            SecurityProperty::Integrity => PropertyCheck {
                property,
                satisfied: true, // AEAD provides integrity
                reason: "AEAD cipher suites provide authenticated encryption with integrity"
                    .to_string(),
            },
            SecurityProperty::QuantumResistance => {
                let satisfied = config.mode != TlsMode::Classic;
                PropertyCheck {
                    property,
                    satisfied,
                    reason: if satisfied {
                        format!("{:?} mode uses ML-KEM for quantum resistance", config.mode)
                    } else {
                        "Classic mode uses only classical key exchange (X25519)".to_string()
                    },
                }
            }
        }
    }
}

impl Default for SecurityProperties {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_properties_satisfied_by_default() {
        let checker = SecurityProperties::new();
        let config = TlsConfig::new();
        assert!(checker.all_satisfied(&config));
    }

    #[test]
    fn test_full_properties_fail_without_mtls() {
        let checker = SecurityProperties::full();
        let config = TlsConfig::new(); // no client auth
        assert!(!checker.all_satisfied(&config));
        let checks = checker.verify(&config);
        let client_auth =
            checks.iter().find(|c| c.property == SecurityProperty::ClientAuthentication);
        assert!(client_auth.is_some());
        assert!(!client_auth.expect("checked above").satisfied);
    }

    #[test]
    fn test_quantum_resistance_fails_classic_mode() {
        let checker = SecurityProperties::new().require(SecurityProperty::QuantumResistance);
        let config = TlsConfig { mode: TlsMode::Classic, ..TlsConfig::default() };
        assert!(!checker.all_satisfied(&config));
    }

    #[test]
    fn test_quantum_resistance_passes_hybrid_mode() {
        let checker = SecurityProperties::new().require(SecurityProperty::QuantumResistance);
        let config = TlsConfig::new(); // default is Hybrid
        assert!(checker.all_satisfied(&config));
    }

    #[test]
    fn test_verify_returns_all_checks() {
        let checker = SecurityProperties::new();
        let config = TlsConfig::new();
        let checks = checker.verify(&config);
        assert_eq!(checks.len(), 4);
    }

    #[test]
    fn test_require_adds_property() {
        let checker = SecurityProperties::new().require(SecurityProperty::QuantumResistance);
        let config = TlsConfig::new();
        let checks = checker.verify(&config);
        assert_eq!(checks.len(), 5);
    }

    #[test]
    fn test_require_deduplicates() {
        let checker = SecurityProperties::new().require(SecurityProperty::Confidentiality); // already included
        let config = TlsConfig::new();
        let checks = checker.verify(&config);
        assert_eq!(checks.len(), 4); // should not add duplicate
    }

    #[test]
    fn test_property_check_debug() {
        let check = PropertyCheck {
            property: SecurityProperty::Confidentiality,
            satisfied: true,
            reason: "test".to_string(),
        };
        let debug = format!("{:?}", check);
        assert!(debug.contains("Confidentiality"));
    }

    #[test]
    fn test_security_property_eq() {
        assert_eq!(SecurityProperty::Confidentiality, SecurityProperty::Confidentiality);
        assert_ne!(SecurityProperty::Confidentiality, SecurityProperty::Integrity);
    }
}
