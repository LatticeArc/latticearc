#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Property-based testing helpers for TLS security properties.
//!
//! Provides generators and property assertions for testing TLS configurations
//! across a wide range of inputs. These are used by proptest/quickcheck harnesses
//! in the test suite.

use crate::{TlsConfig, TlsMode};

/// Generates TLS configurations for property-based testing.
pub struct PropertyTests {
    /// Include Classic mode in generated configs
    include_classic: bool,
    /// Include Hybrid mode in generated configs
    include_hybrid: bool,
    /// Include PQ mode in generated configs
    include_pq: bool,
}

impl PropertyTests {
    /// Create a new property test generator with all modes enabled.
    #[must_use]
    pub fn new() -> Self {
        Self { include_classic: true, include_hybrid: true, include_pq: true }
    }

    /// Only generate PQ-safe configurations (Hybrid + PQ).
    #[must_use]
    pub fn pq_safe_only() -> Self {
        Self { include_classic: false, include_hybrid: true, include_pq: true }
    }

    /// Generate all test configurations based on enabled modes.
    #[must_use]
    pub fn generate_configs(&self) -> Vec<TlsConfig> {
        let mut configs = Vec::new();

        if self.include_classic {
            configs.push(TlsConfig { mode: TlsMode::Classic, ..TlsConfig::default() });
        }
        if self.include_hybrid {
            configs.push(TlsConfig::new()); // default is Hybrid
        }
        if self.include_pq {
            configs.push(TlsConfig { mode: TlsMode::Pq, ..TlsConfig::default() });
        }

        configs
    }

    /// Assert a property holds for all generated configurations.
    ///
    /// Returns the number of configurations checked, or panics with
    /// the first failing configuration's index.
    ///
    /// # Panics
    ///
    /// Panics if any generated configuration fails the property check.
    pub fn assert_for_all<F>(&self, property_name: &str, check: F) -> usize
    where
        F: Fn(&TlsConfig) -> bool,
    {
        let configs = self.generate_configs();
        for (i, config) in configs.iter().enumerate() {
            assert!(
                check(config),
                "Property '{}' failed for config #{} (mode: {:?})",
                property_name,
                i,
                config.mode
            );
        }
        configs.len()
    }

    /// Check a property for all generated configs, returning failures instead of panicking.
    #[must_use]
    pub fn check_for_all<F>(&self, check: F) -> Vec<(usize, TlsMode)>
    where
        F: Fn(&TlsConfig) -> bool,
    {
        let configs = self.generate_configs();
        configs
            .iter()
            .enumerate()
            .filter(|(_, config)| !check(config))
            .map(|(i, config)| (i, config.mode))
            .collect()
    }
}

impl Default for PropertyTests {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_configs() {
        let pt = PropertyTests::new();
        let configs = pt.generate_configs();
        assert_eq!(configs.len(), 3);
        assert_eq!(configs[0].mode, TlsMode::Classic);
        assert_eq!(configs[1].mode, TlsMode::Hybrid);
        assert_eq!(configs[2].mode, TlsMode::Pq);
    }

    #[test]
    fn test_pq_safe_only() {
        let pt = PropertyTests::pq_safe_only();
        let configs = pt.generate_configs();
        assert_eq!(configs.len(), 2);
        assert!(configs.iter().all(|c| c.mode != TlsMode::Classic));
    }

    #[test]
    fn test_assert_for_all_passes() {
        let pt = PropertyTests::new();
        let count = pt.assert_for_all("TLS 1.3 min version", |config| {
            config.min_protocol_version == Some(rustls::ProtocolVersion::TLSv1_3)
        });
        assert_eq!(count, 3);
    }

    #[test]
    fn test_check_for_all_no_failures() {
        let pt = PropertyTests::new();
        let failures = pt.check_for_all(|_config| true);
        assert!(failures.is_empty());
    }

    #[test]
    fn test_check_for_all_finds_classic() {
        let pt = PropertyTests::new();
        let failures = pt.check_for_all(|config| config.mode != TlsMode::Classic);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].1, TlsMode::Classic);
    }
}
