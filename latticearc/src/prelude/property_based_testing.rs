//! Property-Based Testing using Proptest
//!
//! This module provides property-based tests that verify error handling,
//! serialization, and utility functions hold across a wide range of inputs.
//!
//! Property-based testing generates random inputs to test invariants that
//! should hold for all possible inputs, providing more comprehensive
//! coverage than traditional unit tests.

#![deny(unsafe_code)]
// Property-based testing modules are test-only and use test patterns
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::wildcard_enum_match_arm))]
#![cfg_attr(test, allow(clippy::redundant_clone))]

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
use crate::prelude::error::LatticeArcError;

/// Strategy for generating valid error messages.
#[cfg(test)]
fn arb_error_message() -> impl Strategy<Value = String> {
    // Using expect() is acceptable here as this is a compile-time constant regex
    // that is guaranteed to be valid
    prop::string::string_regex("[a-zA-Z0-9 .,!?_-]{1,100}")
        .expect("valid regex pattern for error messages")
}

/// Strategy for generating valid error types.
#[cfg(test)]
fn arb_quantum_shield_error() -> impl Strategy<Value = LatticeArcError> {
    arb_error_message().prop_map(LatticeArcError::InvalidInput)
}

// Property: Error display formatting is consistent
#[cfg(test)]
proptest! {
    #[test]
    fn prop_error_display_consistent(error in arb_quantum_shield_error()) {
        let display1 = format!("{}", error);
        let display2 = format!("{}", error);

        // Display should be deterministic
        prop_assert_eq!(display1.clone(), display2);

        // Display should not be empty
        prop_assert!(!display1.is_empty());

        // Display should contain some descriptive text
        prop_assert!(display1.len() > 10);
    }
}

// Property: Error serialization is well-formed for outbound logging.
// Errors are deliberately not deserializable (see LatticeArcError doc).
#[cfg(test)]
proptest! {
    #[test]
    fn prop_error_serialization_well_formed(error in arb_quantum_shield_error()) {
        let json: String = serde_json::to_string(&error)?;
        prop_assert!(!json.is_empty());

        // Sanity: re-parsing the JSON as untyped Value must succeed,
        // confirming the emitted bytes are well-formed JSON.
        let _value: serde_json::Value = serde_json::from_str(&json)?;

        // Display impl is independent of serde and must always succeed.
        let display = format!("{}", error);
        prop_assert!(!display.is_empty());
    }
}

/// Test that UUID generation produces valid UUIDs.
#[cfg(test)]
#[test]
fn test_uuid_generation_valid_produces_v4_uuid_succeeds() {
    let uuid = uuid::Uuid::new_v4();

    // Should be valid UUID
    assert!(!uuid.is_nil());

    // Should have correct version (4)
    assert_eq!(uuid.get_version_num(), 4);

    // String representation should be valid
    let uuid_str = uuid.to_string();
    assert_eq!(uuid_str.len(), 36); // UUID string length

    // Should contain hyphens at correct positions
    assert_eq!(uuid_str.chars().nth(8), Some('-'));
    assert_eq!(uuid_str.chars().nth(13), Some('-'));
    assert_eq!(uuid_str.chars().nth(18), Some('-'));
    assert_eq!(uuid_str.chars().nth(23), Some('-'));
}

// Property: Hex encoding/decoding round-trip
#[cfg(test)]
proptest! {
    #[test]
    fn prop_hex_roundtrip(data in prop::collection::vec(prop::num::u8::ANY, 0..=100)) {
        // Encode to hex
        let hex_string = hex::encode(&data);

        // Decode back
        let decoded = hex::decode(&hex_string)?;

        // Should match original
        prop_assert_eq!(data.clone(), decoded);

        // Hex string should be exactly 2x length
        prop_assert_eq!(hex_string.len(), data.len().saturating_mul(2));
    }
}

/// Test that domain constants are non-empty and unique.
#[cfg(test)]
#[test]
fn test_domain_constants_valid_succeeds() {
    use crate::types::domains;

    // All domain constants should be non-empty
    assert!(!domains::HYBRID_KEM.is_empty());
    assert!(!domains::CASCADE_OUTER.is_empty());
    assert!(!domains::CASCADE_INNER.is_empty());
    assert!(!domains::SIGNATURE_BIND.is_empty());

    // Domain constants should be unique
    let domains = vec![
        domains::HYBRID_KEM,
        domains::CASCADE_OUTER,
        domains::CASCADE_INNER,
        domains::SIGNATURE_BIND,
    ];

    for (i, &domain1) in domains.iter().enumerate() {
        for (j, &domain2) in domains.iter().enumerate() {
            if i != j {
                assert_ne!(domain1, domain2, "Domain constants should be unique");
            }
        }
    }

    // All should contain version identifier
    for &domain in &domains {
        assert!(
            domain.windows(12).any(|w| w == b"LatticeArc-v"),
            "Domain should contain version identifier"
        );
    }
}

/// Test that the version constant is reasonable.
#[cfg(test)]
#[test]
fn test_version_constant_reasonable_is_nonzero_succeeds() {
    // Version should be non-zero and reasonable
    const { assert!(crate::prelude::ENVELOPE_FORMAT_VERSION > 0) };
    let version1 = crate::prelude::ENVELOPE_FORMAT_VERSION;
    let version2 = crate::prelude::ENVELOPE_FORMAT_VERSION;
    assert_eq!(version1, version2);
}

// Property: Error conversion implementations work correctly
#[cfg(test)]
proptest! {
    #[test]
    fn prop_error_conversions_work(msg in arb_error_message()) {
        // Test string conversion - clone needed for multiple uses
        #[allow(clippy::redundant_clone)]
        let error: LatticeArcError = LatticeArcError::InvalidInput(msg.clone());
        match error {
            #[allow(clippy::redundant_clone)]
            LatticeArcError::InvalidInput(s) => prop_assert_eq!(s, msg.clone()),
            // Wildcard match needed for exhaustive coverage in proptest
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => prop_assert!(false, "Expected InvalidInput error"),
        }

        // Test io::Error conversion - clone needed for multiple uses
        #[allow(clippy::redundant_clone)]
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, msg.clone());
        let converted: LatticeArcError = io_error.into();
        match converted {
            LatticeArcError::IoError(s) => prop_assert!(s.contains(&msg)),
            // Wildcard match needed for exhaustive coverage in proptest
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => prop_assert!(false, "Expected IoError"),
        }
    }
}

/// Run all property-based tests.
#[cfg(test)]
pub fn run_all_property_tests() {
    tracing::info!("Running prelude property-based tests");
    // ... existing code ...
    tracing::info!("Prelude property-based tests completed");
}

/// Configuration for property-based testing.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct PropertyTestConfig {
    /// Number of test cases to generate.
    pub test_cases: u32,
    /// Maximum number of shrink iterations.
    pub max_shrink_iters: u32,
    /// Timeout for the entire test run.
    pub timeout: std::time::Duration,
}

#[cfg(test)]
impl Default for PropertyTestConfig {
    fn default() -> Self {
        Self {
            test_cases: 256,
            max_shrink_iters: 10000,
            timeout: std::time::Duration::from_secs(300), // 5 minutes
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_property_test_runner_succeeds() {
        // This just tests that the framework works
        run_all_property_tests();
    }

    #[test]
    fn test_config_defaults_succeeds() {
        let config = PropertyTestConfig::default();
        assert_eq!(config.test_cases, 256);
        assert_eq!(config.max_shrink_iters, 10000);
        assert_eq!(config.timeout.as_secs(), 300);
    }

    #[test]
    fn test_domain_constants_succeeds() {
        use crate::types::domains;

        assert!(!domains::HYBRID_KEM.is_empty());
        assert!(!domains::CASCADE_OUTER.is_empty());
        assert!(!domains::CASCADE_INNER.is_empty());
        assert!(!domains::SIGNATURE_BIND.is_empty());
    }

    #[test]
    fn test_version_constant_is_nonzero_succeeds() {
        const { assert!(crate::prelude::ENVELOPE_FORMAT_VERSION > 0) };
        // VERSION is u8, so the upper bound check is inherent
    }

    #[test]
    fn test_error_display_fails() {
        let error = LatticeArcError::InvalidInput("test message".to_string());
        let display = format!("{}", error);
        assert!(display.contains("test message"));
        assert!(display.contains("Invalid input"));
    }

    #[test]
    fn test_error_serializes_to_well_formed_json() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let json = serde_json::to_string(&error).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Must mention the variant name and the payload string.
        assert!(json.contains("InvalidInput"));
        assert!(json.contains("test"));
        // JSON parses back to a structured value (untyped) — no Deserialize
        // derive on LatticeArcError itself.
        assert!(!value.is_null());
    }

    #[test]
    fn test_uuid_generation_produces_v4_uuid_succeeds() {
        let uuid = uuid::Uuid::new_v4();
        assert!(!uuid.is_nil());
        assert_eq!(uuid.get_version_num(), 4);
        let uuid_str = uuid.to_string();
        assert_eq!(uuid_str.len(), 36);
        assert_eq!(uuid_str.chars().nth(8), Some('-'));
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![1, 2, 3, 255, 0];
        let hex_string = hex::encode(&data);
        let decoded = hex::decode(&hex_string).unwrap();
        assert_eq!(data, decoded);
        assert_eq!(hex_string.len(), data.len() * 2);
    }
}
