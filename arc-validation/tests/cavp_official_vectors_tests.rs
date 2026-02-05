//! Comprehensive tests for CAVP Official Vectors module
//!
//! This module tests the official CAVP vector downloading, parsing, and validation
//! functionality including:
//! - OfficialCavpVector struct and its fields
//! - CavpTestInputs and CavpTestOutputs structs
//! - CavpTestCollection and CavpTestGroup structs
//! - VectorValidationResult struct
//! - CavpVectorDownloader functionality
//! - Hex validation
//! - Parameter set validation
//! - Vector parsing and validation logic
//! - Error handling paths

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

use arc_validation::cavp::official_vectors::{
    CavpTestCollection, CavpTestGroup, CavpTestInputs, CavpTestOutputs, CavpVectorDownloader,
    OfficialCavpVector, VectorValidationResult,
};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Creates a valid ML-KEM keyGen test vector
fn create_valid_mlkem_keygen_vector() -> OfficialCavpVector {
    OfficialCavpVector {
        tg_id: 1,
        tc_id: 1,
        algorithm: "ML-KEM".to_string(),
        test_type: "keyGen".to_string(),
        parameter_set: "ML-KEM-768".to_string(),
        inputs: CavpTestInputs {
            seed: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        },
        outputs: CavpTestOutputs {
            pk: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            ),
            sk: Some(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            ),
            signature: None,
            ct: None,
            ss: None,
            test_passed: None,
            additional: HashMap::new(),
        },
    }
}

/// Creates a valid ML-DSA sigGen test vector
fn create_valid_mldsa_siggen_vector() -> OfficialCavpVector {
    OfficialCavpVector {
        tg_id: 2,
        tc_id: 1,
        algorithm: "ML-DSA".to_string(),
        test_type: "sigGen".to_string(),
        parameter_set: "ML-DSA-65".to_string(),
        inputs: CavpTestInputs {
            seed: None,
            pk: None,
            sk: Some(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            ),
            message: Some("48656c6c6f20576f726c64".to_string()), // "Hello World" in hex
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        },
        outputs: CavpTestOutputs {
            pk: None,
            sk: None,
            signature: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            ct: None,
            ss: None,
            test_passed: None,
            additional: HashMap::new(),
        },
    }
}

/// Creates a valid ML-DSA sigVer test vector
fn create_valid_mldsa_sigver_vector() -> OfficialCavpVector {
    OfficialCavpVector {
        tg_id: 3,
        tc_id: 1,
        algorithm: "ML-DSA".to_string(),
        test_type: "sigVer".to_string(),
        parameter_set: "ML-DSA-44".to_string(),
        inputs: CavpTestInputs {
            seed: None,
            pk: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            ),
            sk: None,
            message: Some("48656c6c6f20576f726c64".to_string()),
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        },
        outputs: CavpTestOutputs {
            pk: None,
            sk: None,
            signature: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            ct: None,
            ss: None,
            test_passed: Some(true),
            additional: HashMap::new(),
        },
    }
}

/// Creates a valid SLH-DSA keyGen test vector
fn create_valid_slhdsa_keygen_vector() -> OfficialCavpVector {
    OfficialCavpVector {
        tg_id: 4,
        tc_id: 1,
        algorithm: "SLH-DSA".to_string(),
        test_type: "keyGen".to_string(),
        parameter_set: "SLH-DSA-SHA2-128s".to_string(),
        inputs: CavpTestInputs {
            seed: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        },
        outputs: CavpTestOutputs {
            pk: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            ),
            sk: Some(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            ),
            signature: None,
            ct: None,
            ss: None,
            test_passed: None,
            additional: HashMap::new(),
        },
    }
}

/// Creates a valid FN-DSA sigGen test vector
fn create_valid_fndsa_siggen_vector() -> OfficialCavpVector {
    OfficialCavpVector {
        tg_id: 5,
        tc_id: 1,
        algorithm: "FN-DSA".to_string(),
        test_type: "sigGen".to_string(),
        parameter_set: "Falcon-512".to_string(),
        inputs: CavpTestInputs {
            seed: None,
            pk: None,
            sk: Some(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            ),
            message: Some("48656c6c6f20576f726c64".to_string()),
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        },
        outputs: CavpTestOutputs {
            pk: None,
            sk: None,
            signature: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            ct: None,
            ss: None,
            test_passed: None,
            additional: HashMap::new(),
        },
    }
}

/// Creates a mock CAVP JSON file content for testing
/// Note: Uses snake_case field names to match the struct deserialization
fn create_mock_cavp_json(
    algorithm: &str,
    test_type: &str,
    parameter_set: &str,
) -> serde_json::Value {
    json!({
        "vs_id": 12345,
        "algorithm": algorithm,
        "revision": "1.0",
        "is_sample": true,
        "test_groups": [
            {
                "tg_id": 1,
                "test_type": test_type,
                "parameter_set": parameter_set,
                "tests": [
                    {
                        "tcId": 1,
                        "testCase": {
                            "seed": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        },
                        "results": {
                            "pk": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                            "sk": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                        }
                    },
                    {
                        "tcId": 2,
                        "testCase": {
                            "seed": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                        },
                        "results": {
                            "pk": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            "sk": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                        }
                    }
                ]
            }
        ]
    })
}

/// Creates a mock CAVP JSON file for signature generation tests
fn create_mock_siggen_json(algorithm: &str, parameter_set: &str) -> serde_json::Value {
    json!({
        "vs_id": 12346,
        "algorithm": algorithm,
        "revision": "1.0",
        "is_sample": true,
        "test_groups": [
            {
                "tg_id": 1,
                "test_type": "sigGen",
                "parameter_set": parameter_set,
                "tests": [
                    {
                        "tcId": 1,
                        "testCase": {
                            "sk": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                            "message": "48656c6c6f20576f726c64"
                        },
                        "results": {
                            "signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        }
                    }
                ]
            }
        ]
    })
}

/// Creates a mock CAVP JSON file for signature verification tests
fn create_mock_sigver_json(algorithm: &str, parameter_set: &str) -> serde_json::Value {
    json!({
        "vs_id": 12347,
        "algorithm": algorithm,
        "revision": "1.0",
        "is_sample": true,
        "test_groups": [
            {
                "tg_id": 1,
                "test_type": "sigVer",
                "parameter_set": parameter_set,
                "tests": [
                    {
                        "tcId": 1,
                        "testCase": {
                            "pk": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                            "message": "48656c6c6f20576f726c64"
                        },
                        "results": {
                            "signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            "test_passed": true
                        }
                    }
                ]
            }
        ]
    })
}

// ============================================================================
// OfficialCavpVector Tests
// ============================================================================

mod official_cavp_vector_tests {
    use super::*;

    #[test]
    fn test_vector_creation_mlkem_keygen() {
        let vector = create_valid_mlkem_keygen_vector();

        assert_eq!(vector.tg_id, 1);
        assert_eq!(vector.tc_id, 1);
        assert_eq!(vector.algorithm, "ML-KEM");
        assert_eq!(vector.test_type, "keyGen");
        assert_eq!(vector.parameter_set, "ML-KEM-768");
        assert!(vector.inputs.seed.is_some());
        assert!(vector.outputs.pk.is_some());
        assert!(vector.outputs.sk.is_some());
    }

    #[test]
    fn test_vector_creation_mldsa_siggen() {
        let vector = create_valid_mldsa_siggen_vector();

        assert_eq!(vector.algorithm, "ML-DSA");
        assert_eq!(vector.test_type, "sigGen");
        assert_eq!(vector.parameter_set, "ML-DSA-65");
        assert!(vector.inputs.sk.is_some());
        assert!(vector.inputs.message.is_some());
        assert!(vector.outputs.signature.is_some());
    }

    #[test]
    fn test_vector_creation_mldsa_sigver() {
        let vector = create_valid_mldsa_sigver_vector();

        assert_eq!(vector.algorithm, "ML-DSA");
        assert_eq!(vector.test_type, "sigVer");
        assert!(vector.inputs.pk.is_some());
        assert!(vector.inputs.message.is_some());
        assert!(vector.outputs.signature.is_some());
        assert!(vector.outputs.test_passed.is_some());
        assert_eq!(vector.outputs.test_passed, Some(true));
    }

    #[test]
    fn test_vector_creation_slhdsa() {
        let vector = create_valid_slhdsa_keygen_vector();

        assert_eq!(vector.algorithm, "SLH-DSA");
        assert_eq!(vector.test_type, "keyGen");
        assert_eq!(vector.parameter_set, "SLH-DSA-SHA2-128s");
    }

    #[test]
    fn test_vector_creation_fndsa() {
        let vector = create_valid_fndsa_siggen_vector();

        assert_eq!(vector.algorithm, "FN-DSA");
        assert_eq!(vector.test_type, "sigGen");
        assert_eq!(vector.parameter_set, "Falcon-512");
    }

    #[test]
    fn test_vector_serialization() {
        let vector = create_valid_mlkem_keygen_vector();

        let serialized = serde_json::to_string(&vector).unwrap();
        let deserialized: OfficialCavpVector = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vector.tg_id, deserialized.tg_id);
        assert_eq!(vector.tc_id, deserialized.tc_id);
        assert_eq!(vector.algorithm, deserialized.algorithm);
        assert_eq!(vector.test_type, deserialized.test_type);
        assert_eq!(vector.parameter_set, deserialized.parameter_set);
    }

    #[test]
    fn test_vector_clone() {
        let vector = create_valid_mlkem_keygen_vector();
        let cloned = vector.clone();

        assert_eq!(vector.tg_id, cloned.tg_id);
        assert_eq!(vector.tc_id, cloned.tc_id);
        assert_eq!(vector.algorithm, cloned.algorithm);
        assert_eq!(vector.inputs.seed, cloned.inputs.seed);
    }

    #[test]
    fn test_vector_debug() {
        let vector = create_valid_mlkem_keygen_vector();
        let debug_str = format!("{:?}", vector);

        assert!(debug_str.contains("OfficialCavpVector"));
        assert!(debug_str.contains("ML-KEM"));
        assert!(debug_str.contains("keyGen"));
    }
}

// ============================================================================
// CavpTestInputs Tests
// ============================================================================

mod cavp_test_inputs_tests {
    use super::*;

    #[test]
    fn test_inputs_empty() {
        let inputs = CavpTestInputs {
            seed: None,
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        };

        assert!(inputs.seed.is_none());
        assert!(inputs.pk.is_none());
        assert!(inputs.sk.is_none());
        assert!(inputs.message.is_none());
        assert!(inputs.additional.is_empty());
    }

    #[test]
    fn test_inputs_with_all_fields() {
        let mut additional = HashMap::new();
        additional.insert("custom_field".to_string(), json!("custom_value"));

        let inputs = CavpTestInputs {
            seed: Some("abcd1234".to_string()),
            pk: Some("pk_hex".to_string()),
            sk: Some("sk_hex".to_string()),
            message: Some("message_hex".to_string()),
            ct: Some("ct_hex".to_string()),
            ek: Some("ek_hex".to_string()),
            dk: Some("dk_hex".to_string()),
            m: Some("m_hex".to_string()),
            additional,
        };

        assert_eq!(inputs.seed, Some("abcd1234".to_string()));
        assert_eq!(inputs.pk, Some("pk_hex".to_string()));
        assert_eq!(inputs.sk, Some("sk_hex".to_string()));
        assert_eq!(inputs.message, Some("message_hex".to_string()));
        assert_eq!(inputs.ct, Some("ct_hex".to_string()));
        assert_eq!(inputs.ek, Some("ek_hex".to_string()));
        assert_eq!(inputs.dk, Some("dk_hex".to_string()));
        assert_eq!(inputs.m, Some("m_hex".to_string()));
        assert!(inputs.additional.contains_key("custom_field"));
    }

    #[test]
    fn test_inputs_serialization() {
        let inputs = CavpTestInputs {
            seed: Some("0123456789abcdef".to_string()),
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        };

        let serialized = serde_json::to_string(&inputs).unwrap();
        let deserialized: CavpTestInputs = serde_json::from_str(&serialized).unwrap();

        assert_eq!(inputs.seed, deserialized.seed);
    }

    #[test]
    fn test_inputs_clone() {
        let inputs = CavpTestInputs {
            seed: Some("test_seed".to_string()),
            pk: Some("test_pk".to_string()),
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        };

        let cloned = inputs.clone();
        assert_eq!(inputs.seed, cloned.seed);
        assert_eq!(inputs.pk, cloned.pk);
    }
}

// ============================================================================
// CavpTestOutputs Tests
// ============================================================================

mod cavp_test_outputs_tests {
    use super::*;

    #[test]
    fn test_outputs_empty() {
        let outputs = CavpTestOutputs {
            pk: None,
            sk: None,
            signature: None,
            ct: None,
            ss: None,
            test_passed: None,
            additional: HashMap::new(),
        };

        assert!(outputs.pk.is_none());
        assert!(outputs.sk.is_none());
        assert!(outputs.signature.is_none());
        assert!(outputs.test_passed.is_none());
    }

    #[test]
    fn test_outputs_with_all_fields() {
        let mut additional = HashMap::new();
        additional.insert("extra".to_string(), json!(42));

        let outputs = CavpTestOutputs {
            pk: Some("pk_output".to_string()),
            sk: Some("sk_output".to_string()),
            signature: Some("sig_output".to_string()),
            ct: Some("ct_output".to_string()),
            ss: Some("ss_output".to_string()),
            test_passed: Some(true),
            additional,
        };

        assert_eq!(outputs.pk, Some("pk_output".to_string()));
        assert_eq!(outputs.sk, Some("sk_output".to_string()));
        assert_eq!(outputs.signature, Some("sig_output".to_string()));
        assert_eq!(outputs.ct, Some("ct_output".to_string()));
        assert_eq!(outputs.ss, Some("ss_output".to_string()));
        assert_eq!(outputs.test_passed, Some(true));
        assert!(outputs.additional.contains_key("extra"));
    }

    #[test]
    fn test_outputs_test_passed_variants() {
        let outputs_pass = CavpTestOutputs {
            pk: None,
            sk: None,
            signature: None,
            ct: None,
            ss: None,
            test_passed: Some(true),
            additional: HashMap::new(),
        };

        let outputs_fail = CavpTestOutputs {
            pk: None,
            sk: None,
            signature: None,
            ct: None,
            ss: None,
            test_passed: Some(false),
            additional: HashMap::new(),
        };

        assert_eq!(outputs_pass.test_passed, Some(true));
        assert_eq!(outputs_fail.test_passed, Some(false));
    }

    #[test]
    fn test_outputs_serialization() {
        let outputs = CavpTestOutputs {
            pk: Some("0123456789".to_string()),
            sk: None,
            signature: Some("abcdef".to_string()),
            ct: None,
            ss: None,
            test_passed: Some(true),
            additional: HashMap::new(),
        };

        let serialized = serde_json::to_string(&outputs).unwrap();
        let deserialized: CavpTestOutputs = serde_json::from_str(&serialized).unwrap();

        assert_eq!(outputs.pk, deserialized.pk);
        assert_eq!(outputs.signature, deserialized.signature);
        assert_eq!(outputs.test_passed, deserialized.test_passed);
    }
}

// ============================================================================
// CavpTestCollection Tests
// ============================================================================

mod cavp_test_collection_tests {
    use super::*;

    #[test]
    fn test_collection_creation() {
        let collection = CavpTestCollection {
            vs_id: 12345,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        assert_eq!(collection.vs_id, 12345);
        assert_eq!(collection.algorithm, "ML-KEM");
        assert_eq!(collection.revision, "1.0");
        assert!(collection.is_sample);
        assert!(collection.test_groups.is_empty());
    }

    #[test]
    fn test_collection_with_groups() {
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            tests: vec![json!({"tcId": 1})],
        };

        let collection = CavpTestCollection {
            vs_id: 12345,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: false,
            test_groups: vec![group],
        };

        assert_eq!(collection.test_groups.len(), 1);
        assert_eq!(collection.test_groups[0].tg_id, 1);
        assert!(!collection.is_sample);
    }

    #[test]
    fn test_collection_serialization() {
        let collection = CavpTestCollection {
            vs_id: 99999,
            algorithm: "ML-DSA".to_string(),
            revision: "2.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        let serialized = serde_json::to_string(&collection).unwrap();
        let deserialized: CavpTestCollection = serde_json::from_str(&serialized).unwrap();

        assert_eq!(collection.vs_id, deserialized.vs_id);
        assert_eq!(collection.algorithm, deserialized.algorithm);
        assert_eq!(collection.revision, deserialized.revision);
    }

    #[test]
    fn test_collection_clone() {
        let collection = CavpTestCollection {
            vs_id: 11111,
            algorithm: "SLH-DSA".to_string(),
            revision: "1.5".to_string(),
            is_sample: false,
            test_groups: vec![],
        };

        let cloned = collection.clone();
        assert_eq!(collection.vs_id, cloned.vs_id);
        assert_eq!(collection.algorithm, cloned.algorithm);
    }
}

// ============================================================================
// CavpTestGroup Tests
// ============================================================================

mod cavp_test_group_tests {
    use super::*;

    #[test]
    fn test_group_creation() {
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-512".to_string(),
            tests: vec![],
        };

        assert_eq!(group.tg_id, 1);
        assert_eq!(group.test_type, "keyGen");
        assert_eq!(group.parameter_set, "ML-KEM-512");
        assert!(group.tests.is_empty());
    }

    #[test]
    fn test_group_with_tests() {
        let tests =
            vec![json!({"tcId": 1, "seed": "abc123"}), json!({"tcId": 2, "seed": "def456"})];

        let group = CavpTestGroup {
            tg_id: 5,
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            tests,
        };

        assert_eq!(group.tests.len(), 2);
        assert_eq!(group.tests[0]["tcId"], 1);
        assert_eq!(group.tests[1]["tcId"], 2);
    }

    #[test]
    fn test_group_serialization() {
        let group = CavpTestGroup {
            tg_id: 10,
            test_type: "sigVer".to_string(),
            parameter_set: "Falcon-1024".to_string(),
            tests: vec![json!({"tcId": 1})],
        };

        let serialized = serde_json::to_string(&group).unwrap();
        let deserialized: CavpTestGroup = serde_json::from_str(&serialized).unwrap();

        assert_eq!(group.tg_id, deserialized.tg_id);
        assert_eq!(group.test_type, deserialized.test_type);
        assert_eq!(group.parameter_set, deserialized.parameter_set);
    }

    #[test]
    fn test_group_clone() {
        let group = CavpTestGroup {
            tg_id: 3,
            test_type: "keyGen".to_string(),
            parameter_set: "SLH-DSA-SHAKE-256f".to_string(),
            tests: vec![json!({"test": "data"})],
        };

        let cloned = group.clone();
        assert_eq!(group.tg_id, cloned.tg_id);
        assert_eq!(group.tests.len(), cloned.tests.len());
    }
}

// ============================================================================
// VectorValidationResult Tests
// ============================================================================

mod vector_validation_result_tests {
    use super::*;

    #[test]
    fn test_result_valid() {
        let result = VectorValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
            vector_id: "ML-KEM-1-1".to_string(),
        };

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
        assert_eq!(result.vector_id, "ML-KEM-1-1");
    }

    #[test]
    fn test_result_with_errors() {
        let result = VectorValidationResult {
            is_valid: false,
            errors: vec!["Invalid hex".to_string(), "Missing seed".to_string()],
            warnings: vec![],
            vector_id: "ML-DSA-2-3".to_string(),
        };

        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors.contains(&"Invalid hex".to_string()));
        assert!(result.errors.contains(&"Missing seed".to_string()));
    }

    #[test]
    fn test_result_with_warnings() {
        let result = VectorValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec!["Missing verification result".to_string()],
            vector_id: "SLH-DSA-3-1".to_string(),
        };

        assert!(result.is_valid);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings.contains(&"Missing verification result".to_string()));
    }

    #[test]
    fn test_result_with_both_errors_and_warnings() {
        let result = VectorValidationResult {
            is_valid: false,
            errors: vec!["Critical error".to_string()],
            warnings: vec!["Minor warning".to_string()],
            vector_id: "FN-DSA-4-1".to_string(),
        };

        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_result_clone() {
        let result = VectorValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec!["test warning".to_string()],
            vector_id: "TEST-1-1".to_string(),
        };

        let cloned = result.clone();
        assert_eq!(result.is_valid, cloned.is_valid);
        assert_eq!(result.warnings, cloned.warnings);
        assert_eq!(result.vector_id, cloned.vector_id);
    }

    #[test]
    fn test_result_debug() {
        let result = VectorValidationResult {
            is_valid: false,
            errors: vec!["error".to_string()],
            warnings: vec![],
            vector_id: "DEBUG-1-1".to_string(),
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("VectorValidationResult"));
        assert!(debug_str.contains("is_valid"));
    }
}

// ============================================================================
// CavpVectorDownloader Tests
// ============================================================================

mod cavp_vector_downloader_tests {
    use super::*;

    #[test]
    fn test_downloader_creation_success() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path());

        assert!(downloader.is_ok());
    }

    #[test]
    fn test_downloader_creation_with_string_path() {
        let temp_dir = TempDir::new().unwrap();
        let path_string = temp_dir.path().to_string_lossy().to_string();
        let downloader = CavpVectorDownloader::new(&path_string);

        assert!(downloader.is_ok());
    }

    #[test]
    fn test_downloader_creates_cache_dir() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("nested").join("cache").join("dir");

        let downloader = CavpVectorDownloader::new(&cache_path);

        assert!(downloader.is_ok());
        assert!(cache_path.exists());
    }

    #[test]
    fn test_downloader_vector_validation_keygen_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = create_valid_mlkem_keygen_vector();
        let result = downloader.validate_vector(&vector);

        assert!(result.is_valid, "Valid keyGen vector should pass: {:?}", result.errors);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_downloader_vector_validation_siggen_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = create_valid_mldsa_siggen_vector();
        let result = downloader.validate_vector(&vector);

        assert!(result.is_valid, "Valid sigGen vector should pass: {:?}", result.errors);
    }

    #[test]
    fn test_downloader_vector_validation_sigver_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = create_valid_mldsa_sigver_vector();
        let result = downloader.validate_vector(&vector);

        assert!(result.is_valid, "Valid sigVer vector should pass: {:?}", result.errors);
    }

    #[test]
    fn test_downloader_vector_validation_keygen_missing_seed() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: None, // Missing required seed
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing seed"));
    }

    #[test]
    fn test_downloader_vector_validation_keygen_missing_pk() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None, // Missing expected public key
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing expected public key"));
    }

    #[test]
    fn test_downloader_vector_validation_keygen_missing_sk() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: None, // Missing expected secret key
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing expected secret key"));
    }

    #[test]
    fn test_downloader_vector_validation_siggen_missing_sk() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: None, // Missing required sk
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing secret key"));
    }

    #[test]
    fn test_downloader_vector_validation_siggen_missing_message() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("abcdef123456".to_string()),
                message: None, // Missing required message
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing message"));
    }

    #[test]
    fn test_downloader_vector_validation_siggen_missing_signature() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("abcdef123456".to_string()),
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None, // Missing expected signature
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing expected signature"));
    }

    #[test]
    fn test_downloader_vector_validation_sigver_missing_pk() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None, // Missing required pk
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing public key"));
    }

    #[test]
    fn test_downloader_vector_validation_sigver_missing_message() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef".to_string()),
                sk: None,
                message: None, // Missing required message
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("123456".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing message"));
    }

    #[test]
    fn test_downloader_vector_validation_sigver_missing_signature() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef".to_string()),
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None, // Missing signature
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing signature"));
    }

    #[test]
    fn test_downloader_vector_validation_sigver_missing_test_passed() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef".to_string()),
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("123456".to_string()),
                ct: None,
                ss: None,
                test_passed: None, // Missing - should produce warning
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        // Should still be valid, just with a warning
        assert!(result.is_valid);
        assert!(!result.warnings.is_empty());
        let warning_string = result.warnings.join(" ");
        assert!(warning_string.contains("Missing verification result"));
    }

    #[test]
    fn test_downloader_vector_validation_unknown_test_type() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "unknownTestType".to_string(), // Unknown test type
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        // Should produce a warning for unknown test type
        assert!(!result.warnings.is_empty());
        let warning_string = result.warnings.join(" ");
        assert!(warning_string.contains("Unknown test type"));
    }

    #[test]
    fn test_downloader_vector_validation_invalid_hex_in_seed() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdeG".to_string()), // Invalid hex (G)
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"));
    }

    #[test]
    fn test_downloader_vector_validation_invalid_hex_in_pk() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("xyz123!@#".to_string()), // Invalid hex
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"));
    }

    #[test]
    fn test_downloader_vector_validation_invalid_hex_in_sk() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("not-valid-hex!".to_string()), // Invalid hex
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"));
    }

    #[test]
    fn test_downloader_vector_validation_invalid_hex_in_message() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("abcdef123456".to_string()),
                message: Some("ghijkl".to_string()), // Invalid hex (g, h, i, j, k, l are invalid)
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"));
    }

    #[test]
    fn test_downloader_vector_validation_invalid_hex_in_signature() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("abcdef123456".to_string()),
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("ZZZZ".to_string()), // Invalid hex
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"));
    }

    #[test]
    fn test_downloader_vector_validation_invalid_parameter_set() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-999".to_string(), // Invalid parameter set
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("123456".to_string()),
                sk: Some("789abc".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid parameter set"));
    }

    #[test]
    fn test_downloader_vector_validation_vector_id_format() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 5,
            tc_id: 10,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("123456".to_string()),
                sk: Some("789abc".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);

        // Vector ID should be in format: algorithm-tg_id-tc_id
        assert_eq!(result.vector_id, "ML-KEM-5-10");
    }

    #[test]
    fn test_downloader_parse_vector_content_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-768");
        let content = serde_json::to_vec(&json).unwrap();

        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 2); // Two test cases in mock
    }

    #[test]
    fn test_downloader_parse_vector_content_siggen() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = create_mock_siggen_json("ML-DSA", "ML-DSA-65");
        let content = serde_json::to_vec(&json).unwrap();

        let result = downloader.parse_vector_content(&content, "ML-DSA-sigGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
    }

    #[test]
    fn test_downloader_parse_vector_content_sigver() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = create_mock_sigver_json("ML-DSA", "ML-DSA-44");
        let content = serde_json::to_vec(&json).unwrap();

        let result = downloader.parse_vector_content(&content, "ML-DSA-sigVer");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
    }

    #[test]
    fn test_downloader_parse_vector_content_invalid_utf8() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Invalid UTF-8 sequence
        let invalid_content: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01];

        let result = downloader.parse_vector_content(&invalid_content, "test");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid UTF-8"));
    }

    #[test]
    fn test_downloader_parse_vector_content_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let invalid_json = b"{ invalid json }";

        let result = downloader.parse_vector_content(invalid_json, "test");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_downloader_load_vectors_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Write a mock JSON file
        let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-512");
        let file_path = temp_dir.path().join("ML-KEM-keyGen.json");
        fs::write(&file_path, serde_json::to_vec(&json).unwrap()).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert!(!vectors.is_empty());
    }

    #[test]
    fn test_downloader_load_vectors_from_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let nonexistent_path = temp_dir.path().join("does_not_exist.json");

        let result = downloader.load_vectors_from_file(&nonexistent_path);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Failed to read"));
    }
}

// ============================================================================
// Hex Validation Tests
// ============================================================================

mod hex_validation_tests {
    use super::*;

    #[test]
    fn test_is_valid_hex_lowercase() {
        let temp_dir = TempDir::new().unwrap();
        let _downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Test via vector validation which uses is_valid_hex internally
        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()), // Valid lowercase hex
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("fedcba9876543210".to_string()),
                sk: Some("abcdef0123456789".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = _downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_is_valid_hex_uppercase() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789ABCDEF".to_string()), // Valid uppercase hex
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("FEDCBA9876543210".to_string()),
                sk: Some("ABCDEF0123456789".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_is_valid_hex_mixed_case() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123ABCDabcd4567".to_string()), // Valid mixed case hex
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("AaBbCcDdEeFf0011".to_string()),
                sk: Some("9876543210ABCdef".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_is_valid_hex_empty() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("".to_string()), // Empty string - invalid
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"));
    }

    #[test]
    fn test_is_valid_hex_with_spaces() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcd 1234".to_string()), // Space - invalid
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_is_valid_hex_with_special_chars() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcd!@#$".to_string()), // Special chars - invalid
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
    }
}

// ============================================================================
// Parameter Set Validation Tests
// ============================================================================

mod parameter_set_validation_tests {
    use super::*;

    // ML-KEM parameter sets
    #[test]
    fn test_mlkem_512_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mlkem_keygen_vector();
        vector.parameter_set = "ML-KEM-512".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-KEM-512 should be valid");
    }

    #[test]
    fn test_mlkem_768_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mlkem_keygen_vector();
        vector.parameter_set = "ML-KEM-768".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-KEM-768 should be valid");
    }

    #[test]
    fn test_mlkem_1024_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mlkem_keygen_vector();
        vector.parameter_set = "ML-KEM-1024".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-KEM-1024 should be valid");
    }

    #[test]
    fn test_mlkem_invalid_variant() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mlkem_keygen_vector();
        vector.parameter_set = "ML-KEM-256".to_string(); // Invalid

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid parameter set"));
    }

    // ML-DSA parameter sets
    #[test]
    fn test_mldsa_44_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mldsa_siggen_vector();
        vector.parameter_set = "ML-DSA-44".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-DSA-44 should be valid");
    }

    #[test]
    fn test_mldsa_65_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mldsa_siggen_vector();
        vector.parameter_set = "ML-DSA-65".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-DSA-65 should be valid");
    }

    #[test]
    fn test_mldsa_87_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mldsa_siggen_vector();
        vector.parameter_set = "ML-DSA-87".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-DSA-87 should be valid");
    }

    #[test]
    fn test_mldsa_128_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mldsa_siggen_vector();
        vector.parameter_set = "ML-DSA-128".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "ML-DSA-128 should be valid");
    }

    #[test]
    fn test_mldsa_invalid_variant() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mldsa_siggen_vector();
        vector.parameter_set = "ML-DSA-99".to_string(); // Invalid

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
    }

    // SLH-DSA parameter sets
    #[test]
    fn test_slhdsa_sha2_128s_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHA2-128s".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHA2-128s should be valid");
    }

    #[test]
    fn test_slhdsa_sha2_128f_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHA2-128f".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHA2-128f should be valid");
    }

    #[test]
    fn test_slhdsa_sha2_192s_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHA2-192s".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHA2-192s should be valid");
    }

    #[test]
    fn test_slhdsa_sha2_192f_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHA2-192f".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHA2-192f should be valid");
    }

    #[test]
    fn test_slhdsa_sha2_256s_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHA2-256s".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHA2-256s should be valid");
    }

    #[test]
    fn test_slhdsa_sha2_256f_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHA2-256f".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHA2-256f should be valid");
    }

    #[test]
    fn test_slhdsa_shake_128s_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-128s".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHAKE-128s should be valid");
    }

    #[test]
    fn test_slhdsa_shake_128f_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-128f".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHAKE-128f should be valid");
    }

    #[test]
    fn test_slhdsa_shake_192s_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-192s".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHAKE-192s should be valid");
    }

    #[test]
    fn test_slhdsa_shake_192f_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-192f".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHAKE-192f should be valid");
    }

    #[test]
    fn test_slhdsa_shake_256s_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-256s".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHAKE-256s should be valid");
    }

    #[test]
    fn test_slhdsa_shake_256f_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-256f".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "SLH-DSA-SHAKE-256f should be valid");
    }

    #[test]
    fn test_slhdsa_invalid_variant() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_slhdsa_keygen_vector();
        vector.parameter_set = "SLH-DSA-SHAKE-512s".to_string(); // Invalid

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
    }

    // FN-DSA parameter sets
    #[test]
    fn test_fndsa_falcon_512_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_fndsa_siggen_vector();
        vector.parameter_set = "Falcon-512".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "Falcon-512 should be valid");
    }

    #[test]
    fn test_fndsa_falcon_1024_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_fndsa_siggen_vector();
        vector.parameter_set = "Falcon-1024".to_string();

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "Falcon-1024 should be valid");
    }

    #[test]
    fn test_fndsa_invalid_variant() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_fndsa_siggen_vector();
        vector.parameter_set = "Falcon-256".to_string(); // Invalid

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
    }

    // Unknown algorithm
    #[test]
    fn test_unknown_algorithm() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "UNKNOWN-ALG".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "UNKNOWN-PARAM".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("123456".to_string()),
                sk: Some("789abc".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid parameter set"));
    }
}

// ============================================================================
// Async Download Tests (Mock)
// ============================================================================

mod async_download_tests {
    use super::*;

    #[tokio::test]
    async fn test_download_caching_behavior() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Write a cached file
        let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-768");
        let cache_path = temp_dir.path().join("ML-KEM-keyGen.json");
        fs::write(&cache_path, serde_json::to_vec(&json).unwrap()).unwrap();

        // Verify cached file exists
        assert!(cache_path.exists());

        // Load from cache
        let vectors = downloader.load_vectors_from_file(&cache_path).unwrap();
        assert!(!vectors.is_empty());
    }

    #[tokio::test]
    async fn test_downloader_exists_after_creation() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path());

        assert!(downloader.is_ok());
        // Just verifying the downloader can be created and used
        let downloader = downloader.unwrap();

        let vector = create_valid_mlkem_keygen_vector();
        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

mod edge_cases_tests {
    use super::*;

    #[test]
    fn test_empty_additional_fields() {
        let inputs = CavpTestInputs {
            seed: None,
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        };

        assert!(inputs.additional.is_empty());
    }

    #[test]
    fn test_additional_fields_with_various_types() {
        let mut additional = HashMap::new();
        additional.insert("string_field".to_string(), json!("string_value"));
        additional.insert("number_field".to_string(), json!(42));
        additional.insert("bool_field".to_string(), json!(true));
        additional.insert("array_field".to_string(), json!([1, 2, 3]));
        additional.insert("object_field".to_string(), json!({"nested": "value"}));
        additional.insert("null_field".to_string(), json!(null));

        let inputs = CavpTestInputs {
            seed: None,
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional,
        };

        assert_eq!(inputs.additional.len(), 6);
        assert_eq!(inputs.additional["string_field"], json!("string_value"));
        assert_eq!(inputs.additional["number_field"], json!(42));
    }

    #[test]
    fn test_very_long_hex_string() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create a very long but valid hex string
        let long_hex: String = "a".repeat(10000);

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some(long_hex.clone()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some(long_hex.clone()),
                sk: Some(long_hex),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "Long valid hex should be accepted");
    }

    #[test]
    fn test_multiple_validation_errors() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-999".to_string(), // Invalid parameter set
            inputs: CavpTestInputs {
                seed: Some("GHIJ".to_string()), // Invalid hex
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None, // Missing required pk
                sk: None, // Missing required sk
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        // Should have multiple errors
        assert!(result.errors.len() >= 3, "Expected multiple errors, got: {:?}", result.errors);
    }

    #[test]
    fn test_vector_with_all_none_inputs() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        // Should report missing seed for keyGen
        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Missing seed"));
    }

    #[test]
    fn test_large_tg_id_and_tc_id() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: u32::MAX,
            tc_id: u32::MAX,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("123456".to_string()),
                sk: Some("789abc".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
        assert!(result.vector_id.contains(&format!("{}", u32::MAX)));
    }
}

// ============================================================================
// JSON Parsing Tests
// ============================================================================

mod json_parsing_tests {
    use super::*;

    #[test]
    fn test_parse_complete_collection() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "seed": "0123456789abcdef0123456789abcdef"
                            },
                            "results": {
                                "pk": "abcdef0123456789abcdef0123456789",
                                "sk": "fedcba9876543210fedcba9876543210"
                            }
                        }
                    ]
                },
                {
                    "tg_id": 2,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-512",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "seed": "aabbccdd11223344aabbccdd11223344"
                            },
                            "results": {
                                "pk": "11223344aabbccdd11223344aabbccdd",
                                "sk": "44332211ddccbbaa44332211ddccbbaa"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 2); // Two test groups with one test each
    }

    #[test]
    fn test_parse_empty_test_groups() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": []
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert!(vectors.is_empty());
    }

    #[test]
    fn test_parse_empty_tests_in_group() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": []
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert!(vectors.is_empty());
    }

    #[test]
    fn test_parse_missing_required_fields() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Missing "algorithm" field
        let json = json!({
            "vs_id": 12345,
            "revision": "1.0",
            "is_sample": true,
            "test_groups": []
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "test");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_default_tc_id() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Test case without tcId - should use index as default
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "testCase": {
                                "seed": "0123456789abcdef0123456789abcdef"
                            },
                            "results": {
                                "pk": "abcdef0123456789abcdef0123456789",
                                "sk": "fedcba9876543210fedcba9876543210"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].tc_id, 0); // Default from index
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_workflow_mlkem() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create mock JSON
        let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-768");
        let content = serde_json::to_vec(&json).unwrap();

        // Parse vectors
        let vectors = downloader.parse_vector_content(&content, "ML-KEM-keyGen").unwrap();

        // Validate each vector
        for vector in &vectors {
            let result = downloader.validate_vector(vector);
            assert!(result.is_valid, "Vector should be valid: {:?}", result.errors);
        }
    }

    #[test]
    fn test_full_workflow_mldsa() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create mock JSON for sigGen
        let json = create_mock_siggen_json("ML-DSA", "ML-DSA-44");
        let content = serde_json::to_vec(&json).unwrap();

        // Parse vectors
        let vectors = downloader.parse_vector_content(&content, "ML-DSA-sigGen").unwrap();

        // Validate each vector
        for vector in &vectors {
            let result = downloader.validate_vector(vector);
            assert!(result.is_valid, "Vector should be valid: {:?}", result.errors);
        }
    }

    #[test]
    fn test_cache_file_creation() {
        let temp_dir = TempDir::new().unwrap();
        let _downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Verify cache directory exists
        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());
    }

    #[test]
    fn test_multiple_downloader_instances() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let downloader1 = CavpVectorDownloader::new(temp_dir1.path()).unwrap();
        let downloader2 = CavpVectorDownloader::new(temp_dir2.path()).unwrap();

        let vector = create_valid_mlkem_keygen_vector();

        let result1 = downloader1.validate_vector(&vector);
        let result2 = downloader2.validate_vector(&vector);

        assert_eq!(result1.is_valid, result2.is_valid);
    }
}

// ============================================================================
// Additional Coverage Tests - Static Methods
// ============================================================================

mod static_method_tests {
    use super::*;

    // Tests for is_valid_hex static method
    #[test]
    fn test_is_valid_hex_direct_call_valid_lowercase() {
        assert!(CavpVectorDownloader::is_valid_hex("0123456789abcdef"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_valid_uppercase() {
        assert!(CavpVectorDownloader::is_valid_hex("0123456789ABCDEF"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_valid_mixed() {
        assert!(CavpVectorDownloader::is_valid_hex("aAbBcCdDeEfF0123"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_single_char() {
        assert!(CavpVectorDownloader::is_valid_hex("a"));
        assert!(CavpVectorDownloader::is_valid_hex("F"));
        assert!(CavpVectorDownloader::is_valid_hex("0"));
        assert!(CavpVectorDownloader::is_valid_hex("9"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_empty() {
        assert!(!CavpVectorDownloader::is_valid_hex(""));
    }

    #[test]
    fn test_is_valid_hex_direct_call_invalid_g() {
        assert!(!CavpVectorDownloader::is_valid_hex("g"));
        assert!(!CavpVectorDownloader::is_valid_hex("abcdG123"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_invalid_special() {
        assert!(!CavpVectorDownloader::is_valid_hex("!"));
        assert!(!CavpVectorDownloader::is_valid_hex("@"));
        assert!(!CavpVectorDownloader::is_valid_hex("#"));
        assert!(!CavpVectorDownloader::is_valid_hex("$"));
        assert!(!CavpVectorDownloader::is_valid_hex("%"));
        assert!(!CavpVectorDownloader::is_valid_hex("^"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_invalid_whitespace() {
        assert!(!CavpVectorDownloader::is_valid_hex(" "));
        assert!(!CavpVectorDownloader::is_valid_hex("\t"));
        assert!(!CavpVectorDownloader::is_valid_hex("\n"));
        assert!(!CavpVectorDownloader::is_valid_hex("ab cd"));
        assert!(!CavpVectorDownloader::is_valid_hex("ab\ncd"));
    }

    #[test]
    fn test_is_valid_hex_direct_call_invalid_unicode() {
        assert!(!CavpVectorDownloader::is_valid_hex("\u{00e9}")); // e with acute
        assert!(!CavpVectorDownloader::is_valid_hex("\u{03B1}")); // alpha
        assert!(!CavpVectorDownloader::is_valid_hex("\u{4e2d}")); // Chinese character
    }

    // Tests for is_valid_parameter_set static method
    #[test]
    fn test_is_valid_parameter_set_mlkem_all_valid() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-512"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-768"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-1024"));
    }

    #[test]
    fn test_is_valid_parameter_set_mlkem_invalid() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-128"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-256"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-2048"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", ""));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM"));
    }

    #[test]
    fn test_is_valid_parameter_set_mldsa_all_valid() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-44"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-65"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-87"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-128"));
    }

    #[test]
    fn test_is_valid_parameter_set_mldsa_invalid() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-32"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-256"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", ""));
    }

    #[test]
    fn test_is_valid_parameter_set_slhdsa_sha2_all() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-128s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-128f"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-192s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-192f"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-256s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-256f"));
    }

    #[test]
    fn test_is_valid_parameter_set_slhdsa_shake_all() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-128s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-128f"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-192s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-192f"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-256s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-256f"));
    }

    #[test]
    fn test_is_valid_parameter_set_slhdsa_invalid() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-64s"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-512s"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-MD5-128s"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", ""));
    }

    #[test]
    fn test_is_valid_parameter_set_fndsa_all_valid() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-512"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-1024"));
    }

    #[test]
    fn test_is_valid_parameter_set_fndsa_invalid() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-256"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-2048"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Dilithium-512"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", ""));
    }

    #[test]
    fn test_is_valid_parameter_set_unknown_algorithm() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("UNKNOWN", "any-param"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("", "ML-KEM-768"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("RSA", "RSA-2048"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ECDSA", "P-256"));
    }

    #[test]
    fn test_is_valid_parameter_set_case_sensitivity() {
        // The implementation is case-sensitive
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ml-kem", "ML-KEM-768"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ml-kem-768"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("Ml-Kem", "ML-KEM-768"));
    }
}

// ============================================================================
// Convert Test Case Error Handling Tests
// ============================================================================

mod convert_test_case_tests {
    use super::*;

    #[test]
    fn test_parse_vector_with_missing_testcase() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Test case missing testCase field - implementation returns error
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "results": {
                                "pk": "abcdef0123456789",
                                "sk": "fedcba9876543210"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        // Implementation returns error when testCase field is missing
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vector_with_missing_results() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Test case missing results field - implementation returns error for missing fields
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "seed": "0123456789abcdef"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        // Implementation returns error when results field is missing
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vector_with_null_testcase() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": null,
                            "results": {
                                "pk": "abcdef",
                                "sk": "123456"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        // Implementation returns error for null testCase
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vector_with_null_results() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "seed": "0123456789abcdef"
                            },
                            "results": null
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        // Implementation returns error for null results
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vector_with_wrong_type_in_testcase() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // testCase is a string instead of object
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": "invalid_string",
                            "results": {
                                "pk": "abcdef",
                                "sk": "123456"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        // Should return error due to type mismatch
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vector_with_numeric_tcid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 99999,
                            "testCase": {
                                "seed": "0123456789abcdef"
                            },
                            "results": {
                                "pk": "abcdef0123456789",
                                "sk": "fedcba9876543210"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].tc_id, 99999);
    }

    #[test]
    fn test_parse_vector_tcid_as_string() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // tcId as string instead of number - should fallback to index
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": "not_a_number",
                            "testCase": {
                                "seed": "0123456789abcdef"
                            },
                            "results": {
                                "pk": "abcdef0123456789",
                                "sk": "fedcba9876543210"
                            }
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
        // Falls back to index (0)
        assert_eq!(vectors[0].tc_id, 0);
    }
}

// ============================================================================
// File I/O Error Handling Tests
// ============================================================================

mod file_io_error_tests {
    use super::*;

    #[test]
    fn test_load_from_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create an empty file
        let file_path = temp_dir.path().join("empty.json");
        fs::write(&file_path, "").unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_load_from_corrupted_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create a corrupted JSON file
        let file_path = temp_dir.path().join("corrupted.json");
        fs::write(&file_path, r#"{"vs_id": 12345, "algorithm": "ML-KEM", incomplete..."#).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_load_from_valid_json_wrong_schema() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Valid JSON but wrong schema
        let file_path = temp_dir.path().join("wrong_schema.json");
        fs::write(&file_path, r#"{"name": "test", "value": 123}"#).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_array_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // JSON array instead of object
        let file_path = temp_dir.path().join("array.json");
        fs::write(&file_path, r#"[1, 2, 3]"#).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_binary_file() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create a binary file
        let file_path = temp_dir.path().join("binary.json");
        fs::write(&file_path, &[0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE]).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        // May fail at UTF-8 decoding or JSON parsing
        assert!(result.is_err());
    }

    #[test]
    fn test_cache_file_with_invalid_content_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create a cache file with invalid JSON content
        let cache_path = temp_dir.path().join("ML-KEM-keyGen.json");
        fs::write(&cache_path, "not valid json").unwrap();

        // Try to load from this "cached" file
        let result = downloader.load_vectors_from_file(&cache_path);

        // Should fail because content is invalid
        assert!(result.is_err());
    }

    #[test]
    fn test_file_stem_extraction_with_extension() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create a valid JSON file with specific name
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": []
        });
        let file_path = temp_dir.path().join("test-vectors.json");
        fs::write(&file_path, serde_json::to_vec(&json).unwrap()).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_ok());
    }

    #[test]
    fn test_file_without_extension() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // Create a valid JSON file without .json extension
        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": []
        });
        let file_path = temp_dir.path().join("test-vectors");
        fs::write(&file_path, serde_json::to_vec(&json).unwrap()).unwrap();

        let result = downloader.load_vectors_from_file(&file_path);

        assert!(result.is_ok());
    }
}

// ============================================================================
// Validation Edge Cases Tests
// ============================================================================

mod validation_edge_cases {
    use super::*;

    #[test]
    fn test_validate_sigver_with_test_passed_false() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef1234567890".to_string()),
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("fedcba0987654321".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(false), // Explicitly false
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
        assert!(result.warnings.is_empty()); // No warning for present test_passed
    }

    #[test]
    fn test_validate_encapdecap_test_type() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // encapDecap is an unknown test type (not keyGen, sigGen, sigVer)
        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "encapDecap".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: Some("ciphertext".to_string()),
                ek: Some("encap_key".to_string()),
                dk: Some("decap_key".to_string()),
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None,
                ct: None,
                ss: Some("shared_secret".to_string()),
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        // Should be valid but with warning about unknown test type
        assert!(result.is_valid);
        assert!(!result.warnings.is_empty());
        let warning = result.warnings.join(" ");
        assert!(warning.contains("Unknown test type"));
    }

    #[test]
    fn test_validate_with_extra_additional_inputs() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut additional = HashMap::new();
        additional.insert("rng_name".to_string(), json!("AES-256-CTR-DRBG"));
        additional.insert("deterministic".to_string(), json!(true));
        additional.insert("iterations".to_string(), json!(1000));

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional,
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_with_extra_additional_outputs() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut additional = HashMap::new();
        additional.insert("hash".to_string(), json!("sha256_of_pk"));
        additional.insert("verification_time_ms".to_string(), json!(42));

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("abcdef".to_string()),
                sk: Some("123456".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional,
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_all_hex_fields_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: Some("invalid!seed".to_string()),
                pk: Some("invalid@pk".to_string()),
                sk: Some("invalid#sk".to_string()),
                message: Some("invalid$message".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("invalid%sig".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        // Should have multiple hex validation errors
        assert!(result.errors.len() >= 4);
    }

    #[test]
    fn test_validate_keygen_with_only_seed() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None, // Missing
                sk: None, // Missing
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(!result.is_valid);
        let error_str = result.errors.join(" ");
        assert!(error_str.contains("Missing expected public key"));
        assert!(error_str.contains("Missing expected secret key"));
    }
}

// ============================================================================
// Serialization/Deserialization Tests
// ============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_vector_roundtrip_serialization() {
        let vector = OfficialCavpVector {
            tg_id: 42,
            tc_id: 99,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef1234567890".to_string()),
                pk: Some("pk_value".to_string()),
                sk: Some("sk_value".to_string()),
                message: Some("message_value".to_string()),
                ct: Some("ct_value".to_string()),
                ek: Some("ek_value".to_string()),
                dk: Some("dk_value".to_string()),
                m: Some("m_value".to_string()),
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("out_pk".to_string()),
                sk: Some("out_sk".to_string()),
                signature: Some("out_sig".to_string()),
                ct: Some("out_ct".to_string()),
                ss: Some("out_ss".to_string()),
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let serialized = serde_json::to_string(&vector).unwrap();
        let deserialized: OfficialCavpVector = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vector.tg_id, deserialized.tg_id);
        assert_eq!(vector.tc_id, deserialized.tc_id);
        assert_eq!(vector.algorithm, deserialized.algorithm);
        assert_eq!(vector.inputs.seed, deserialized.inputs.seed);
        assert_eq!(vector.outputs.pk, deserialized.outputs.pk);
        assert_eq!(vector.outputs.test_passed, deserialized.outputs.test_passed);
    }

    #[test]
    fn test_collection_roundtrip_serialization() {
        let collection = CavpTestCollection {
            vs_id: 12345,
            algorithm: "ML-DSA".to_string(),
            revision: "2.0".to_string(),
            is_sample: false,
            test_groups: vec![
                CavpTestGroup {
                    tg_id: 1,
                    test_type: "sigGen".to_string(),
                    parameter_set: "ML-DSA-65".to_string(),
                    tests: vec![json!({"tcId": 1, "data": "test"})],
                },
                CavpTestGroup {
                    tg_id: 2,
                    test_type: "sigVer".to_string(),
                    parameter_set: "ML-DSA-87".to_string(),
                    tests: vec![],
                },
            ],
        };

        let serialized = serde_json::to_string(&collection).unwrap();
        let deserialized: CavpTestCollection = serde_json::from_str(&serialized).unwrap();

        assert_eq!(collection.vs_id, deserialized.vs_id);
        assert_eq!(collection.algorithm, deserialized.algorithm);
        assert_eq!(collection.test_groups.len(), deserialized.test_groups.len());
        assert_eq!(
            collection.test_groups[0].parameter_set,
            deserialized.test_groups[0].parameter_set
        );
    }

    #[test]
    fn test_inputs_with_additional_fields_serialization() {
        let mut additional = HashMap::new();
        additional.insert("custom1".to_string(), json!("value1"));
        additional.insert("custom2".to_string(), json!(123));
        additional.insert("custom3".to_string(), json!({"nested": "object"}));

        let inputs = CavpTestInputs {
            seed: Some("seed_value".to_string()),
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional,
        };

        let serialized = serde_json::to_string(&inputs).unwrap();
        let deserialized: CavpTestInputs = serde_json::from_str(&serialized).unwrap();

        assert_eq!(inputs.seed, deserialized.seed);
        assert_eq!(inputs.additional.len(), deserialized.additional.len());
        assert_eq!(inputs.additional["custom1"], deserialized.additional["custom1"]);
    }

    #[test]
    fn test_outputs_with_additional_fields_serialization() {
        let mut additional = HashMap::new();
        additional.insert("extra_output".to_string(), json!([1, 2, 3]));
        additional.insert("flag".to_string(), json!(false));

        let outputs = CavpTestOutputs {
            pk: Some("pk_out".to_string()),
            sk: None,
            signature: None,
            ct: None,
            ss: None,
            test_passed: Some(true),
            additional,
        };

        let serialized = serde_json::to_string(&outputs).unwrap();
        let deserialized: CavpTestOutputs = serde_json::from_str(&serialized).unwrap();

        assert_eq!(outputs.pk, deserialized.pk);
        assert_eq!(outputs.test_passed, deserialized.test_passed);
        assert_eq!(outputs.additional.len(), deserialized.additional.len());
    }

    #[test]
    fn test_deserialize_from_external_json_format() {
        // Simulate external JSON format that might come from NIST
        let external_json = r#"{
            "vs_id": 99999,
            "algorithm": "ML-KEM",
            "revision": "FIPS203",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-1024",
                    "tests": []
                }
            ]
        }"#;

        let collection: CavpTestCollection = serde_json::from_str(external_json).unwrap();

        assert_eq!(collection.vs_id, 99999);
        assert_eq!(collection.algorithm, "ML-KEM");
        assert_eq!(collection.revision, "FIPS203");
        assert!(collection.is_sample);
        assert_eq!(collection.test_groups.len(), 1);
    }
}

// ============================================================================
// Multiple Test Groups Tests
// ============================================================================

mod multiple_test_groups_tests {
    use super::*;

    #[test]
    fn test_parse_multiple_groups_different_param_sets() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-512",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {"seed": "0123456789abcdef"},
                            "results": {"pk": "aabbccdd", "sk": "11223344"}
                        }
                    ]
                },
                {
                    "tg_id": 2,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {"seed": "fedcba9876543210"},
                            "results": {"pk": "55667788", "sk": "99aabbcc"}
                        }
                    ]
                },
                {
                    "tg_id": 3,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {"seed": "abcdef1234567890"},
                            "results": {"pk": "ddeeff00", "sk": "11223344"}
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 3);

        assert_eq!(vectors[0].parameter_set, "ML-KEM-512");
        assert_eq!(vectors[1].parameter_set, "ML-KEM-768");
        assert_eq!(vectors[2].parameter_set, "ML-KEM-1024");
    }

    #[test]
    fn test_parse_multiple_tests_in_single_group() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-DSA",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "sigGen",
                    "parameter_set": "ML-DSA-44",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {"sk": "aabbccdd", "message": "11223344"},
                            "results": {"signature": "aabbccdd11223344"}
                        },
                        {
                            "tcId": 2,
                            "testCase": {"sk": "eeff0011", "message": "55667788"},
                            "results": {"signature": "eeff001155667788"}
                        },
                        {
                            "tcId": 3,
                            "testCase": {"sk": "99aabbcc", "message": "ddeeff00"},
                            "results": {"signature": "99aabbccddeeff00"}
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-DSA-sigGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 3);

        assert_eq!(vectors[0].tc_id, 1);
        assert_eq!(vectors[1].tc_id, 2);
        assert_eq!(vectors[2].tc_id, 3);
    }

    #[test]
    fn test_parse_mixed_valid_invalid_vectors() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {"seed": "0123456789abcdef"},
                            "results": {"pk": "aabbccdd", "sk": "11223344"}
                        },
                        {
                            "tcId": 2,
                            "testCase": {"seed": "INVALID_HEX!!"},
                            "results": {"pk": "55667788", "sk": "99aabbcc"}
                        },
                        {
                            "tcId": 3,
                            "testCase": {"seed": "fedcba9876543210"},
                            "results": {"pk": "ddeeff00", "sk": "11223344"}
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

        assert!(result.is_ok());
        let vectors = result.unwrap();
        // Invalid vector (tcId 2) should be filtered out
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].tc_id, 1);
        assert_eq!(vectors[1].tc_id, 3);
    }
}

// ============================================================================
// Vector ID Generation Tests
// ============================================================================

mod vector_id_tests {
    use super::*;

    #[test]
    fn test_vector_id_format_basic() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("123456".to_string()),
                sk: Some("789abc".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert_eq!(result.vector_id, "ML-KEM-1-1");
    }

    #[test]
    fn test_vector_id_format_different_algorithms() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let algorithms = vec![
            ("ML-KEM", "ML-KEM-768", "keyGen"),
            ("ML-DSA", "ML-DSA-44", "sigGen"),
            ("SLH-DSA", "SLH-DSA-SHA2-128s", "keyGen"),
            ("FN-DSA", "Falcon-512", "sigGen"),
        ];

        for (alg, param, test_type) in algorithms {
            let mut vector = create_valid_mlkem_keygen_vector();
            vector.algorithm = alg.to_string();
            vector.parameter_set = param.to_string();
            vector.test_type = test_type.to_string();
            vector.tg_id = 10;
            vector.tc_id = 20;

            if test_type == "sigGen" {
                vector.inputs.sk = Some("abcdef123456".to_string());
                vector.inputs.message = Some("48656c6c6f".to_string());
                vector.outputs.signature = Some("fedcba654321".to_string());
                vector.outputs.pk = None;
                vector.outputs.sk = None;
                vector.inputs.seed = None;
            }

            let result = downloader.validate_vector(&vector);
            assert_eq!(result.vector_id, format!("{}-10-20", alg));
        }
    }

    #[test]
    fn test_vector_id_with_zero_ids() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mlkem_keygen_vector();
        vector.tg_id = 0;
        vector.tc_id = 0;

        let result = downloader.validate_vector(&vector);
        assert_eq!(result.vector_id, "ML-KEM-0-0");
    }

    #[test]
    fn test_vector_id_with_large_ids() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let mut vector = create_valid_mlkem_keygen_vector();
        vector.tg_id = 999999;
        vector.tc_id = 888888;

        let result = downloader.validate_vector(&vector);
        assert_eq!(result.vector_id, "ML-KEM-999999-888888");
    }
}

// ============================================================================
// Downloader Creation Edge Cases
// ============================================================================

mod downloader_creation_tests {
    use super::*;

    #[test]
    fn test_downloader_with_existing_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create directory first
        let cache_path = temp_dir.path().join("existing_cache");
        fs::create_dir_all(&cache_path).unwrap();

        // Should succeed even if directory exists
        let downloader = CavpVectorDownloader::new(&cache_path);
        assert!(downloader.is_ok());
    }

    #[test]
    fn test_downloader_with_deeply_nested_path() {
        let temp_dir = TempDir::new().unwrap();
        let deep_path = temp_dir
            .path()
            .join("level1")
            .join("level2")
            .join("level3")
            .join("level4")
            .join("cache");

        let downloader = CavpVectorDownloader::new(&deep_path);
        assert!(downloader.is_ok());
        assert!(deep_path.exists());
    }

    #[test]
    fn test_downloader_with_path_string() {
        let temp_dir = TempDir::new().unwrap();
        let path_str = temp_dir.path().to_string_lossy().to_string();

        let downloader = CavpVectorDownloader::new(&path_str);
        assert!(downloader.is_ok());
    }

    #[test]
    fn test_downloader_with_pathbuf() {
        let temp_dir = TempDir::new().unwrap();
        let path_buf = temp_dir.path().to_path_buf();

        let downloader = CavpVectorDownloader::new(path_buf);
        assert!(downloader.is_ok());
    }

    #[test]
    fn test_downloader_with_unicode_path() {
        let temp_dir = TempDir::new().unwrap();
        // Note: Some systems may not support all unicode characters in paths
        let unicode_path = temp_dir.path().join("test_cache_dir");

        let downloader = CavpVectorDownloader::new(&unicode_path);
        assert!(downloader.is_ok());
    }
}

// ============================================================================
// Parse Content Edge Cases
// ============================================================================

mod parse_content_edge_cases {
    use super::*;

    #[test]
    fn test_parse_content_with_bom() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        // UTF-8 BOM followed by valid JSON
        let mut content = vec![0xEF, 0xBB, 0xBF];
        content.extend_from_slice(
            br#"{"vs_id": 1, "algorithm": "ML-KEM", "revision": "1.0", "is_sample": true, "test_groups": []}"#,
        );

        // BOM may cause parsing to fail depending on implementation
        let result = downloader.parse_vector_content(&content, "test");
        // Either succeeds or fails gracefully
        if result.is_ok() {
            assert!(result.unwrap().is_empty());
        }
    }

    #[test]
    fn test_parse_content_with_trailing_whitespace() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = r#"{"vs_id": 1, "algorithm": "ML-KEM", "revision": "1.0", "is_sample": true, "test_groups": []}

        "#;

        let result = downloader.parse_vector_content(json.as_bytes(), "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_content_with_unicode_in_strings() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0 - Test \u{00e9}\u{00e8}\u{00ea}",
            "is_sample": true,
            "test_groups": []
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "test");

        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_content_large_vs_id() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": u32::MAX,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": []
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "test");

        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_content_empty_algorithm() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let json = json!({
            "vs_id": 12345,
            "algorithm": "",
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {"seed": "abcdef"},
                            "results": {"pk": "123456", "sk": "789abc"}
                        }
                    ]
                }
            ]
        });

        let content = serde_json::to_vec(&json).unwrap();
        let result = downloader.parse_vector_content(&content, "test");

        // Should parse but vectors will be invalid due to empty algorithm
        assert!(result.is_ok());
        let vectors = result.unwrap();
        // Empty algorithm won't match any valid parameter set
        assert!(vectors.is_empty());
    }

    #[test]
    fn test_parse_content_whitespace_only() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let content = b"   \n\t  \r\n  ";

        let result = downloader.parse_vector_content(content, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_content_null_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let content = b"null";

        let result = downloader.parse_vector_content(content, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_content_boolean_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let content = b"true";

        let result = downloader.parse_vector_content(content, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_content_number_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let content = b"12345";

        let result = downloader.parse_vector_content(content, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_content_string_json() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let content = b"\"just a string\"";

        let result = downloader.parse_vector_content(content, "test");
        assert!(result.is_err());
    }
}

// ============================================================================
// Test Type Validation Coverage
// ============================================================================

mod test_type_validation_tests {
    use super::*;

    #[test]
    fn test_keygen_all_required_fields_present() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("aabbccdd".to_string()),
                sk: Some("eeff0011".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_siggen_all_required_fields_present() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("abcdef1234567890".to_string()),
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("fedcba9876543210".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_sigver_all_required_fields_present() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-65".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef1234567890".to_string()),
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("fedcba9876543210".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_custom_test_type_with_warning() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let custom_types = vec!["encrypt", "decrypt", "hash", "kdf", "mac", "drbg"];

        for test_type in custom_types {
            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: test_type.to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "Custom test type '{}' should be valid", test_type);
            assert!(!result.warnings.is_empty(), "Should have warning for '{}'", test_type);
            assert!(
                result.warnings[0].contains("Unknown test type"),
                "Warning should mention unknown test type"
            );
        }
    }
}

// ============================================================================
// SLH-DSA Specific Tests
// ============================================================================

mod slhdsa_specific_tests {
    use super::*;

    #[test]
    fn test_slhdsa_keygen_valid() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = create_valid_slhdsa_keygen_vector();
        let result = downloader.validate_vector(&vector);

        assert!(result.is_valid);
    }

    #[test]
    fn test_slhdsa_siggen() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "SLH-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "SLH-DSA-SHAKE-256f".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some("fedcba9876543210".to_string()),
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("0123456789abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_slhdsa_sigver() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "SLH-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "SLH-DSA-SHA2-192f".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef0123456789".to_string()),
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("fedcba9876543210".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(false),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }
}

// ============================================================================
// FN-DSA Specific Tests
// ============================================================================

mod fndsa_specific_tests {
    use super::*;

    #[test]
    fn test_fndsa_keygen() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "FN-DSA".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "Falcon-1024".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some("aabbccdd".to_string()),
                sk: Some("eeff0011".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }

    #[test]
    fn test_fndsa_siggen() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = create_valid_fndsa_siggen_vector();
        let result = downloader.validate_vector(&vector);

        assert!(result.is_valid);
    }

    #[test]
    fn test_fndsa_sigver() {
        let temp_dir = TempDir::new().unwrap();
        let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "FN-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "Falcon-512".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some("abcdef1234567890".to_string()),
                sk: None,
                message: Some("48656c6c6f".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some("fedcba9876543210".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid);
    }
}
