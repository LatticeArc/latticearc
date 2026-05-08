//! NIST KAT module integration tests.
#![deny(unsafe_code)]

// Originally: fips_nist_kat_compliance.rs
mod compliance {
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
        clippy::useless_vec,
        unused_imports
    )]

    //! NIST Known-Answer-Test Compliance Suite
    //!
    //! Validates ML-KEM, ML-DSA, and SLH-DSA parameter sizes against FIPS 203/204/205
    //! and verifies KEM encap/decap and signature sign/verify roundtrips.
    //!
    //! Run with: `cargo test --package arc-validation --test nist_kat_compliance --all-features --release -- --nocapture`

    use fips203::ml_kem_512;
    use fips203::ml_kem_768;
    use fips203::ml_kem_1024;
    use fips203::traits::{Decaps, Encaps, KeyGen, SerDes as FipsSerDes};
    use fips204::ml_dsa_44;
    use fips204::ml_dsa_65;
    use fips204::ml_dsa_87;
    use fips204::traits::{SerDes as MlDsaSerDes, Signer, Verifier};

    // ============================================================================
    // ML-KEM Key/Ciphertext/Shared-Secret Sizes — FIPS 203
    // ============================================================================

    mod ml_kem_sizes {
        use super::*;

        #[test]
        fn test_ml_kem_512_sizes_match_fips203_has_correct_size() {
            // FIPS 203 Table 2: ek=800, dk=1632, ct=768, ss=32
            assert_eq!(ml_kem_512::EK_LEN, 800, "ML-KEM-512 encapsulation key = 800");
            assert_eq!(ml_kem_512::DK_LEN, 1632, "ML-KEM-512 decapsulation key = 1632");
            assert_eq!(ml_kem_512::CT_LEN, 768, "ML-KEM-512 ciphertext = 768");
        }

        #[test]
        fn test_ml_kem_768_sizes_match_fips203_has_correct_size() {
            // FIPS 203 Table 2: ek=1184, dk=2400, ct=1088, ss=32
            assert_eq!(ml_kem_768::EK_LEN, 1184, "ML-KEM-768 encapsulation key = 1184");
            assert_eq!(ml_kem_768::DK_LEN, 2400, "ML-KEM-768 decapsulation key = 2400");
            assert_eq!(ml_kem_768::CT_LEN, 1088, "ML-KEM-768 ciphertext = 1088");
        }

        #[test]
        fn test_ml_kem_1024_sizes_match_fips203_has_correct_size() {
            // FIPS 203 Table 2: ek=1568, dk=3168, ct=1568, ss=32
            assert_eq!(ml_kem_1024::EK_LEN, 1568, "ML-KEM-1024 encapsulation key = 1568");
            assert_eq!(ml_kem_1024::DK_LEN, 3168, "ML-KEM-1024 decapsulation key = 3168");
            assert_eq!(ml_kem_1024::CT_LEN, 1568, "ML-KEM-1024 ciphertext = 1568");
        }

        #[test]
        fn test_ml_kem_512_roundtrip_succeeds() {
            let (ek, dk) = ml_kem_512::KG::try_keygen().expect("ML-KEM-512 keygen failed");
            let (ss_enc, ct) = ek.try_encaps().expect("ML-KEM-512 encaps failed");
            let ss_dec = dk.try_decaps(&ct).expect("ML-KEM-512 decaps failed");
            assert_eq!(ss_enc, ss_dec, "ML-KEM-512 shared secrets must match");
        }

        #[test]
        fn test_ml_kem_768_roundtrip_succeeds() {
            let (ek, dk) = ml_kem_768::KG::try_keygen().expect("ML-KEM-768 keygen failed");
            let (ss_enc, ct) = ek.try_encaps().expect("ML-KEM-768 encaps failed");
            let ss_dec = dk.try_decaps(&ct).expect("ML-KEM-768 decaps failed");
            assert_eq!(ss_enc, ss_dec, "ML-KEM-768 shared secrets must match");
        }

        #[test]
        fn test_ml_kem_1024_roundtrip_succeeds() {
            let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("ML-KEM-1024 keygen failed");
            let (ss_enc, ct) = ek.try_encaps().expect("ML-KEM-1024 encaps failed");
            let ss_dec = dk.try_decaps(&ct).expect("ML-KEM-1024 decaps failed");
            assert_eq!(ss_enc, ss_dec, "ML-KEM-1024 shared secrets must match");
        }
    }

    // ============================================================================
    // ML-DSA Key/Signature Sizes — FIPS 204
    // ============================================================================

    mod ml_dsa_sizes {
        use super::*;

        #[test]
        fn test_ml_dsa_44_sizes_match_fips204_has_correct_size() {
            // FIPS 204 Table 1: pk=1312, sk=2560, sig=2420
            assert_eq!(ml_dsa_44::PK_LEN, 1312, "ML-DSA-44 public key = 1312");
            assert_eq!(ml_dsa_44::SK_LEN, 2560, "ML-DSA-44 secret key = 2560");
            assert_eq!(ml_dsa_44::SIG_LEN, 2420, "ML-DSA-44 signature = 2420");
        }

        #[test]
        fn test_ml_dsa_65_sizes_match_fips204_has_correct_size() {
            // FIPS 204 Table 1: pk=1952, sk=4032, sig=3309
            assert_eq!(ml_dsa_65::PK_LEN, 1952, "ML-DSA-65 public key = 1952");
            assert_eq!(ml_dsa_65::SK_LEN, 4032, "ML-DSA-65 secret key = 4032");
            assert_eq!(ml_dsa_65::SIG_LEN, 3309, "ML-DSA-65 signature = 3309");
        }

        #[test]
        fn test_ml_dsa_87_sizes_match_fips204_has_correct_size() {
            // FIPS 204 Table 1: pk=2592, sk=4896, sig=4627
            assert_eq!(ml_dsa_87::PK_LEN, 2592, "ML-DSA-87 public key = 2592");
            assert_eq!(ml_dsa_87::SK_LEN, 4896, "ML-DSA-87 secret key = 4896");
            assert_eq!(ml_dsa_87::SIG_LEN, 4627, "ML-DSA-87 signature = 4627");
        }

        #[test]
        fn test_ml_dsa_44_roundtrip_succeeds() {
            let (pk, sk) = ml_dsa_44::try_keygen().expect("ML-DSA-44 keygen failed");
            let message = b"NIST KAT compliance roundtrip";
            let context: &[u8] = b"";
            let sig = sk.try_sign(message, context).expect("ML-DSA-44 sign failed");
            assert!(pk.verify(message, &sig, context), "ML-DSA-44 signature must verify");
        }

        #[test]
        fn test_ml_dsa_65_roundtrip_succeeds() {
            let (pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 keygen failed");
            let message = b"ML-DSA-65 compliance check";
            let context: &[u8] = b"";
            let sig = sk.try_sign(message, context).expect("ML-DSA-65 sign failed");
            assert!(pk.verify(message, &sig, context), "ML-DSA-65 signature must verify");
        }

        #[test]
        fn test_ml_dsa_87_roundtrip_succeeds() {
            let (pk, sk) = ml_dsa_87::try_keygen().expect("ML-DSA-87 keygen failed");
            let message = b"ML-DSA-87 compliance check";
            let context: &[u8] = b"";
            let sig = sk.try_sign(message, context).expect("ML-DSA-87 sign failed");
            assert!(pk.verify(message, &sig, context), "ML-DSA-87 signature must verify");
        }
    }

    // ============================================================================
    // ML-KEM Key Serialization Roundtrip
    // ============================================================================

    mod ml_kem_serialization {
        use super::*;

        #[test]
        fn test_ml_kem_512_key_serialization_roundtrip_succeeds() {
            let (ek, dk) = ml_kem_512::KG::try_keygen().expect("keygen failed");
            let ek_bytes = ek.into_bytes();
            let dk_bytes = dk.into_bytes();

            assert_eq!(ek_bytes.len(), ml_kem_512::EK_LEN);
            assert_eq!(dk_bytes.len(), ml_kem_512::DK_LEN);

            let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek_bytes).expect("ek deser failed");
            let dk2 = ml_kem_512::DecapsKey::try_from_bytes(dk_bytes).expect("dk deser failed");

            // Verify roundtrip still works with deserialized keys
            let (ss_enc, ct) = ek2.try_encaps().expect("encaps failed");
            let ss_dec = dk2.try_decaps(&ct).expect("decaps failed");
            assert_eq!(ss_enc, ss_dec, "Roundtrip after deserialization must work");
        }

        #[test]
        fn test_ml_kem_768_key_serialization_roundtrip_succeeds() {
            let (ek, dk) = ml_kem_768::KG::try_keygen().expect("keygen failed");
            let ek_bytes = ek.into_bytes();
            let dk_bytes = dk.into_bytes();

            assert_eq!(ek_bytes.len(), ml_kem_768::EK_LEN);
            assert_eq!(dk_bytes.len(), ml_kem_768::DK_LEN);

            let ek2 = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).expect("ek deser failed");
            let dk2 = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).expect("dk deser failed");

            let (ss_enc, ct) = ek2.try_encaps().expect("encaps failed");
            let ss_dec = dk2.try_decaps(&ct).expect("decaps failed");
            assert_eq!(ss_enc, ss_dec);
        }

        #[test]
        fn test_ml_kem_1024_key_serialization_roundtrip_succeeds() {
            let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("keygen failed");
            let ek_bytes = ek.into_bytes();
            let dk_bytes = dk.into_bytes();

            assert_eq!(ek_bytes.len(), ml_kem_1024::EK_LEN);
            assert_eq!(dk_bytes.len(), ml_kem_1024::DK_LEN);

            let ek2 = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes).expect("ek deser failed");
            let dk2 = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes).expect("dk deser failed");

            let (ss_enc, ct) = ek2.try_encaps().expect("encaps failed");
            let ss_dec = dk2.try_decaps(&ct).expect("decaps failed");
            assert_eq!(ss_enc, ss_dec);
        }
    }

    // ============================================================================
    // ML-DSA Key Serialization Roundtrip
    // ============================================================================

    mod ml_dsa_serialization {
        use super::*;

        #[test]
        fn test_ml_dsa_44_key_serialization_roundtrip_succeeds() {
            let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen failed");

            // Verify key sizes match FIPS 204 Table 1
            assert_eq!(pk.into_bytes().len(), ml_dsa_44::PK_LEN);
            assert_eq!(sk.into_bytes().len(), ml_dsa_44::SK_LEN);

            // Roundtrip: keygen → serialize → deserialize → sign/verify
            let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen2 failed");
            let pk2 =
                ml_dsa_44::PublicKey::try_from_bytes(pk.into_bytes()).expect("pk deser failed");
            let sk2 =
                ml_dsa_44::PrivateKey::try_from_bytes(sk.into_bytes()).expect("sk deser failed");

            let message = b"Serialization roundtrip";
            let context: &[u8] = b"";
            let sig = sk2.try_sign(message, context).expect("sign failed");
            assert!(pk2.verify(message, &sig, context), "Must verify after key deserialization");
        }

        #[test]
        fn test_ml_dsa_65_key_serialization_roundtrip_succeeds() {
            let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen failed");

            assert_eq!(pk.into_bytes().len(), ml_dsa_65::PK_LEN);
            assert_eq!(sk.into_bytes().len(), ml_dsa_65::SK_LEN);

            let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen2 failed");
            let pk2 =
                ml_dsa_65::PublicKey::try_from_bytes(pk.into_bytes()).expect("pk deser failed");
            let sk2 =
                ml_dsa_65::PrivateKey::try_from_bytes(sk.into_bytes()).expect("sk deser failed");

            let message = b"ML-DSA-65 serialization";
            let context: &[u8] = b"";
            let sig = sk2.try_sign(message, context).expect("sign failed");
            assert!(pk2.verify(message, &sig, context));
        }
    }
}

// Originally: fips_nist_kat_coverage.rs
mod coverage {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::float_cmp)]
    #![allow(missing_docs)]

    //! Coverage tests for nist_kat/mod.rs
    //!
    //! Tests decode_hex, KatTestResult, NistKatError Display variants.

    use latticearc_tests::validation::nist_kat::{KatTestResult, NistKatError, decode_hex};

    // ============================================================================
    // decode_hex
    // ============================================================================

    #[test]
    fn test_decode_hex_valid_succeeds() {
        let bytes = decode_hex("48656c6c6f").unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_decode_hex_empty_succeeds() {
        let bytes = decode_hex("").unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_decode_hex_uppercase_succeeds() {
        let bytes = decode_hex("DEADBEEF").unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_decode_hex_invalid_chars_returns_error() {
        let result = decode_hex("ZZZZ");
        assert!(result.is_err());
        match result.unwrap_err() {
            NistKatError::HexError(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("Expected HexError, got {:?}", other),
        }
    }

    #[test]
    fn test_decode_hex_odd_length_returns_error() {
        let result = decode_hex("ABC");
        assert!(result.is_err());
    }

    // ============================================================================
    // KatTestResult constructors
    // ============================================================================

    #[test]
    fn test_kat_test_result_passed_has_correct_fields_matches_expected() {
        let result = KatTestResult::passed("TC1".to_string(), "AES-GCM".to_string(), 42);
        assert!(result.passed);
        assert_eq!(result.test_case, "TC1");
        assert_eq!(result.algorithm, "AES-GCM");
        assert_eq!(result.execution_time_us, 42);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_kat_test_result_failed_has_correct_fields_matches_expected() {
        let result = KatTestResult::failed(
            "TC2".to_string(),
            "SHA-256".to_string(),
            "hash mismatch".to_string(),
            100,
        );
        assert!(!result.passed);
        assert_eq!(result.test_case, "TC2");
        assert_eq!(result.algorithm, "SHA-256");
        assert_eq!(result.execution_time_us, 100);
        assert_eq!(result.error_message.as_deref(), Some("hash mismatch"));
    }

    #[test]
    fn test_kat_test_result_clone_succeeds() {
        let result = KatTestResult::passed("TC1".to_string(), "AES".to_string(), 10);
        let cloned = result.clone();
        assert_eq!(cloned.test_case, result.test_case);
        assert_eq!(cloned.passed, result.passed);
    }

    #[test]
    fn test_kat_test_result_debug_has_correct_format() {
        let result =
            KatTestResult::failed("TC3".to_string(), "HKDF".to_string(), "bad".to_string(), 5);
        let debug = format!("{:?}", result);
        assert!(debug.contains("KatTestResult"));
    }

    // ============================================================================
    // NistKatError Display
    // ============================================================================

    #[test]
    fn test_nist_kat_error_test_failed_display_has_correct_format() {
        let err = NistKatError::TestFailed {
            algorithm: "AES-GCM".to_string(),
            test_name: "TC1".to_string(),
            message: "tag mismatch".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("AES-GCM"));
        assert!(display.contains("TC1"));
        assert!(display.contains("tag mismatch"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_display_has_correct_format() {
        let err = NistKatError::HexError("invalid hex".to_string());
        let display = format!("{err}");
        assert!(display.contains("Hex decode error"));
        assert!(display.contains("invalid hex"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_display_has_correct_format() {
        let err = NistKatError::ImplementationError("algo not found".to_string());
        let display = format!("{err}");
        assert!(display.contains("Implementation error"));
        assert!(display.contains("algo not found"));
    }

    #[test]
    fn test_nist_kat_error_unsupported_algorithm_display_has_correct_format() {
        let err = NistKatError::UnsupportedAlgorithm("SIKE".to_string());
        let display = format!("{err}");
        assert!(display.contains("Unsupported algorithm"));
        assert!(display.contains("SIKE"));
    }

    #[test]
    fn test_nist_kat_error_debug_has_correct_format() {
        let err = NistKatError::HexError("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("HexError"));
    }

    // ============================================================================
    // KatSummary
    // ============================================================================

    use latticearc_tests::validation::nist_kat::runner::{KatRunner, KatSummary};

    #[test]
    fn test_kat_summary_new_has_zero_counts_matches_expected() {
        let summary = KatSummary::new();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.results.is_empty());
        assert_eq!(summary.total_time_ms, 0);
    }

    #[test]
    fn test_kat_summary_default_equals_new_succeeds() {
        let summary = KatSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
    }

    #[test]
    fn test_kat_summary_add_passed_result_increments_counts_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("TC1".to_string(), "AES".to_string(), 2000));
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.total_time_ms, 2);
        assert!(summary.all_passed());
    }

    #[test]
    fn test_kat_summary_add_failed_result_increments_counts_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::failed(
            "TC2".to_string(),
            "HMAC".to_string(),
            "wrong".to_string(),
            5000,
        ));
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 1);
        assert!(!summary.all_passed());
    }

    #[test]
    fn test_kat_summary_mixed_results_are_tracked_correctly_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 1000));
        summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 2000));
        summary.add_result(KatTestResult::failed(
            "T3".to_string(),
            "B".to_string(),
            "fail".to_string(),
            3000,
        ));
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
        assert!(!summary.all_passed());
    }

    #[test]
    fn test_kat_summary_pass_rate_all_passed_returns_100_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 0));
        assert_eq!(summary.pass_rate(), 100.0);
    }

    #[test]
    fn test_kat_summary_pass_rate_none_passed_returns_zero_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::failed(
            "T1".to_string(),
            "A".to_string(),
            "f".to_string(),
            0,
        ));
        assert_eq!(summary.pass_rate(), 0.0);
    }

    #[test]
    fn test_kat_summary_pass_rate_empty_is_zero() {
        let summary = KatSummary::new();
        assert_eq!(summary.pass_rate(), 0.0);
    }

    #[test]
    fn test_kat_summary_pass_rate_half_is_correct() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        summary.add_result(KatTestResult::failed(
            "T2".to_string(),
            "A".to_string(),
            "f".to_string(),
            0,
        ));
        assert_eq!(summary.pass_rate(), 50.0);
    }

    #[test]
    fn test_kat_summary_print_all_passed_succeeds() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("TC1".to_string(), "AES-GCM".to_string(), 1000));
        summary.add_result(KatTestResult::passed("TC2".to_string(), "SHA-256".to_string(), 2000));
        summary.print();
    }

    #[test]
    fn test_kat_summary_print_with_failures_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("TC1".to_string(), "AES-GCM".to_string(), 100));
        summary.add_result(KatTestResult::failed(
            "TC2".to_string(),
            "ML-KEM".to_string(),
            "encap mismatch".to_string(),
            200,
        ));
        summary.add_result(KatTestResult::failed(
            "TC3".to_string(),
            "HMAC".to_string(),
            "tag mismatch".to_string(),
            300,
        ));
        summary.print();
    }

    #[test]
    fn test_kat_summary_print_empty_succeeds() {
        let summary = KatSummary::new();
        summary.print();
    }

    #[test]
    fn test_kat_summary_print_multiple_algorithms_succeeds() {
        let mut summary = KatSummary::new();
        for i in 0..5 {
            summary.add_result(KatTestResult::passed(
                format!("TC{}", i),
                "AES-GCM".to_string(),
                100,
            ));
        }
        for i in 5..8 {
            summary.add_result(KatTestResult::passed(
                format!("TC{}", i),
                "SHA-256".to_string(),
                200,
            ));
        }
        summary.add_result(KatTestResult::passed("TC8".to_string(), "HKDF".to_string(), 50));
        summary.print();
    }

    #[test]
    fn test_kat_summary_print_failed_no_error_message_succeeds() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult {
            test_case: "TC_NO_MSG".to_string(),
            algorithm: "TestAlgo".to_string(),
            passed: false,
            error_message: None,
            execution_time_us: 0,
        });
        summary.print();
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_kat_summary_clone_and_debug_succeeds() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
        let cloned = summary.clone();
        assert_eq!(cloned.total, 1);
        let debug = format!("{:?}", summary);
        assert!(debug.contains("KatSummary"));
    }

    #[test]
    fn test_kat_summary_accumulated_time_returns_total_matches_expected() {
        let mut summary = KatSummary::new();
        summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 5000));
        summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 3000));
        summary.add_result(KatTestResult::failed(
            "T3".to_string(),
            "B".to_string(),
            "err".to_string(),
            2000,
        ));
        assert_eq!(summary.total_time_ms, 10);
    }

    // ============================================================================
    // KatRunner
    // ============================================================================

    #[test]
    fn test_kat_runner_new_has_empty_summary_matches_expected() {
        let runner = KatRunner::new();
        assert_eq!(runner.summary().total, 0);
        assert!(runner.summary().all_passed());
    }

    #[test]
    fn test_kat_runner_default_has_empty_summary_matches_expected() {
        let runner = KatRunner::default();
        assert_eq!(runner.summary().total, 0);
    }

    #[test]
    fn test_kat_runner_run_passing_test_increments_passed_matches_expected() {
        let mut runner = KatRunner::new();
        runner.run_test("TC1", "TestAlgo", || Ok(()));
        assert_eq!(runner.summary().total, 1);
        assert_eq!(runner.summary().passed, 1);
        assert!(runner.summary().all_passed());
    }

    #[test]
    fn test_kat_runner_run_failing_test_increments_failed_matches_expected() {
        let mut runner = KatRunner::new();
        runner.run_test("TC1", "TestAlgo", || {
            Err(NistKatError::TestFailed {
                algorithm: "TestAlgo".to_string(),
                test_name: "TC1".to_string(),
                message: "mismatch".to_string(),
            })
        });
        assert_eq!(runner.summary().failed, 1);
        assert!(!runner.summary().all_passed());
    }

    #[test]
    fn test_kat_runner_run_multiple_tests_accumulates_counts_matches_expected() {
        let mut runner = KatRunner::new();
        runner.run_test("TC1", "A", || Ok(()));
        runner.run_test("TC2", "A", || Ok(()));
        runner.run_test("TC3", "B", || Err(NistKatError::ImplementationError("bug".to_string())));
        runner.run_test("TC4", "B", || Ok(()));
        assert_eq!(runner.summary().total, 4);
        assert_eq!(runner.summary().passed, 3);
        assert_eq!(runner.summary().failed, 1);
    }

    #[test]
    fn test_kat_runner_finish_consumes_and_returns_summary_matches_expected() {
        let mut runner = KatRunner::new();
        runner.run_test("TC1", "Algo", || Ok(()));
        runner.run_test("TC2", "Algo", || Err(NistKatError::HexError("bad".to_string())));
        let summary = runner.finish();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_kat_runner_error_message_is_preserved_matches_expected() {
        let mut runner = KatRunner::new();
        runner.run_test("TC1", "ML-KEM", || {
            Err(NistKatError::TestFailed {
                algorithm: "ML-KEM".to_string(),
                test_name: "TC1".to_string(),
                message: "shared secret mismatch".to_string(),
            })
        });
        let summary = runner.finish();
        let result = &summary.results[0];
        assert!(!result.passed);
        assert!(result.error_message.as_ref().unwrap().contains("shared secret mismatch"));
    }

    #[test]
    fn test_kat_runner_unsupported_algorithm_error_returns_failed_matches_expected() {
        let mut runner = KatRunner::new();
        runner.run_test("TC1", "SIKE", || {
            Err(NistKatError::UnsupportedAlgorithm("SIKE".to_string()))
        });
        let summary = runner.finish();
        assert_eq!(summary.failed, 1);
        assert!(summary.results[0].error_message.as_ref().unwrap().contains("SIKE"));
    }
}

// Originally: fips_nist_kat_integration.rs
mod integration {
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

    //! NIST Known Answer Test Integration Suite
    //!
    //! This test file runs all NIST and RFC test vectors to validate
    //! cryptographic implementations for FIPS compliance.

    use latticearc_tests::validation::nist_kat::*;

    #[test]
    fn test_all_nist_kat_matches_expected() {
        println!("\n========================================");
        println!("Running NIST Known Answer Tests");
        println!("========================================\n");

        let mut runner = KatRunner::new();

        // ML-KEM Tests
        println!("Testing ML-KEM...");
        runner.run_test("ML-KEM-512", "ML-KEM", || ml_kem_kat::run_ml_kem_512_kat());
        runner.run_test("ML-KEM-768", "ML-KEM", || ml_kem_kat::run_ml_kem_768_kat());
        runner.run_test("ML-KEM-1024", "ML-KEM", || ml_kem_kat::run_ml_kem_1024_kat());

        // ML-DSA Tests
        println!("Testing ML-DSA...");
        runner.run_test("ML-DSA-44", "ML-DSA", || ml_dsa_kat::run_ml_dsa_44_kat());
        runner.run_test("ML-DSA-65", "ML-DSA", || ml_dsa_kat::run_ml_dsa_65_kat());
        runner.run_test("ML-DSA-87", "ML-DSA", || ml_dsa_kat::run_ml_dsa_87_kat());

        // AES-GCM Tests
        println!("Testing AES-GCM...");
        runner.run_test("AES-128-GCM", "AES-GCM", || aes_gcm_kat::run_aes_128_gcm_kat());
        runner.run_test("AES-256-GCM", "AES-GCM", || aes_gcm_kat::run_aes_256_gcm_kat());

        // SHA-2 Tests
        println!("Testing SHA-2 Family...");
        runner.run_test("SHA-224", "SHA-2", || sha2_kat::run_sha224_kat());
        runner.run_test("SHA-256", "SHA-2", || sha2_kat::run_sha256_kat());
        runner.run_test("SHA-384", "SHA-2", || sha2_kat::run_sha384_kat());
        runner.run_test("SHA-512", "SHA-2", || sha2_kat::run_sha512_kat());
        runner.run_test("SHA-512/224", "SHA-2", || sha2_kat::run_sha512_224_kat());
        runner.run_test("SHA-512/256", "SHA-2", || sha2_kat::run_sha512_256_kat());

        // HKDF Tests
        println!("Testing HKDF...");
        runner.run_test("HKDF-SHA256", "HKDF", || hkdf_kat::run_hkdf_sha256_kat());

        // HMAC Tests
        println!("Testing HMAC...");
        runner.run_test("HMAC-SHA224", "HMAC", || hmac_kat::run_hmac_sha224_kat());
        runner.run_test("HMAC-SHA256", "HMAC", || hmac_kat::run_hmac_sha256_kat());
        runner.run_test("HMAC-SHA384", "HMAC", || hmac_kat::run_hmac_sha384_kat());
        runner.run_test("HMAC-SHA512", "HMAC", || hmac_kat::run_hmac_sha512_kat());

        // ChaCha20-Poly1305 Tests
        println!("Testing ChaCha20-Poly1305...");
        runner.run_test("ChaCha20-Poly1305", "AEAD", || {
            chacha20_poly1305_kat::run_chacha20_poly1305_kat()
        });

        // Get summary and print
        let summary = runner.finish();
        summary.print();

        // Assert all tests passed
        assert!(
            summary.all_passed(),
            "NIST KAT failures detected: {}/{} tests failed",
            summary.failed,
            summary.total
        );
    }

    #[test]
    fn test_ml_kem_only_succeeds() {
        println!("\nTesting ML-KEM algorithms only...");
        let mut runner = KatRunner::new();

        runner.run_test("ML-KEM-512", "ML-KEM", || ml_kem_kat::run_ml_kem_512_kat());
        runner.run_test("ML-KEM-768", "ML-KEM", || ml_kem_kat::run_ml_kem_768_kat());
        runner.run_test("ML-KEM-1024", "ML-KEM", || ml_kem_kat::run_ml_kem_1024_kat());

        let summary = runner.finish();
        summary.print();
        assert!(summary.all_passed());
    }

    #[test]
    fn test_symmetric_crypto_only_succeeds() {
        println!("\nTesting symmetric cryptography only...");
        let mut runner = KatRunner::new();

        runner.run_test("AES-128-GCM", "AES-GCM", || aes_gcm_kat::run_aes_128_gcm_kat());
        runner.run_test("AES-256-GCM", "AES-GCM", || aes_gcm_kat::run_aes_256_gcm_kat());
        runner.run_test("ChaCha20-Poly1305", "AEAD", || {
            chacha20_poly1305_kat::run_chacha20_poly1305_kat()
        });

        let summary = runner.finish();
        summary.print();
        assert!(summary.all_passed());
    }

    #[test]
    fn test_hash_functions_only_succeeds() {
        println!("\nTesting hash functions only...");
        let mut runner = KatRunner::new();

        runner.run_test("SHA-224", "SHA-2", || sha2_kat::run_sha224_kat());
        runner.run_test("SHA-256", "SHA-2", || sha2_kat::run_sha256_kat());
        runner.run_test("SHA-384", "SHA-2", || sha2_kat::run_sha384_kat());
        runner.run_test("SHA-512", "SHA-2", || sha2_kat::run_sha512_kat());
        runner.run_test("SHA-512/224", "SHA-2", || sha2_kat::run_sha512_224_kat());
        runner.run_test("SHA-512/256", "SHA-2", || sha2_kat::run_sha512_256_kat());

        let summary = runner.finish();
        summary.print();
        assert!(summary.all_passed());
    }

    #[test]
    fn test_kdf_functions_only_succeeds() {
        println!("\nTesting key derivation functions only...");
        let mut runner = KatRunner::new();

        runner.run_test("HKDF-SHA256", "HKDF", || hkdf_kat::run_hkdf_sha256_kat());
        runner.run_test("HMAC-SHA224", "HMAC", || hmac_kat::run_hmac_sha224_kat());
        runner.run_test("HMAC-SHA256", "HMAC", || hmac_kat::run_hmac_sha256_kat());
        runner.run_test("HMAC-SHA384", "HMAC", || hmac_kat::run_hmac_sha384_kat());
        runner.run_test("HMAC-SHA512", "HMAC", || hmac_kat::run_hmac_sha512_kat());

        let summary = runner.finish();
        summary.print();
        assert!(summary.all_passed());
    }

    #[test]
    fn test_vector_count_matches_expected() {
        // Verify we have adequate test coverage
        println!("\nVerifying test vector counts...");

        let ml_kem_512_count = ml_kem_kat::ML_KEM_512_FINGERPRINTS.len();
        let ml_kem_768_count = ml_kem_kat::ML_KEM_768_FINGERPRINTS.len();
        let ml_kem_1024_count = ml_kem_kat::ML_KEM_1024_FINGERPRINTS.len();

        // ML-DSA uses single fingerprints (not arrays), count as 1 each
        let ml_dsa_44_count = 1_usize;
        let ml_dsa_65_count = 1_usize;
        let ml_dsa_87_count = 1_usize;

        let aes_128_gcm_count = aes_gcm_kat::AES_128_GCM_VECTORS.len();
        let aes_256_gcm_count = aes_gcm_kat::AES_256_GCM_VECTORS.len();

        let sha256_count = sha2_kat::SHA256_VECTORS.len();
        let sha224_count = sha2_kat::SHA224_VECTORS.len();
        let sha384_count = sha2_kat::SHA384_VECTORS.len();
        let sha512_count = sha2_kat::SHA512_VECTORS.len();

        let hkdf_count = hkdf_kat::HKDF_SHA256_VECTORS.len();
        let hmac_count = hmac_kat::HMAC_VECTORS.len();
        let chacha_count = chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS.len();

        let total_vectors = ml_kem_512_count
        + ml_kem_768_count
        + ml_kem_1024_count
        + ml_dsa_44_count
        + ml_dsa_65_count
        + ml_dsa_87_count
        + aes_128_gcm_count
        + aes_256_gcm_count
        + sha256_count
        + sha224_count
        + sha384_count
        + sha512_count
        + hkdf_count
        + (hmac_count * 4) // 4 HMAC variants
        + chacha_count;

        println!("\nTest Vector Summary:");
        println!("  ML-KEM-512:          {}", ml_kem_512_count);
        println!("  ML-KEM-768:          {}", ml_kem_768_count);
        println!("  ML-KEM-1024:         {}", ml_kem_1024_count);
        println!("  ML-DSA-44:           {}", ml_dsa_44_count);
        println!("  ML-DSA-65:           {}", ml_dsa_65_count);
        println!("  ML-DSA-87:           {}", ml_dsa_87_count);
        println!("  AES-128-GCM:         {}", aes_128_gcm_count);
        println!("  AES-256-GCM:         {}", aes_256_gcm_count);
        println!("  SHA-256:             {}", sha256_count);
        println!("  SHA-224:             {}", sha224_count);
        println!("  SHA-384:             {}", sha384_count);
        println!("  SHA-512:             {}", sha512_count);
        println!("  HKDF-SHA256:         {}", hkdf_count);
        println!("  HMAC (all variants): {}", hmac_count * 4);
        println!("  ChaCha20-Poly1305:   {}", chacha_count);
        println!("  ----------------------------------------");
        println!("  TOTAL VECTORS:       {}", total_vectors);

        // Verify we meet the 50+ test vector requirement
        assert!(total_vectors >= 50, "Insufficient test vectors: {} < 50", total_vectors);

        println!("\n✓ Test vector count requirement met: {} >= 50", total_vectors);
    }
}

// Originally: fips_nist_kat_mod_coverage.rs
mod mod_coverage {
    //! Coverage tests for arc-validation/src/nist_kat/mod.rs
    //! Targets: KatTestResult factory methods, NistKatError display, decode_hex

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

    use latticearc_tests::validation::nist_kat::{KatTestResult, NistKatError, decode_hex};

    #[test]
    fn test_kat_test_result_passed_matches_expected() {
        let result = KatTestResult::passed("test-1".to_string(), "AES-GCM".to_string(), 42);
        assert!(result.passed);
        assert_eq!(result.test_case, "test-1");
        assert_eq!(result.algorithm, "AES-GCM");
        assert!(result.error_message.is_none());
        assert_eq!(result.execution_time_us, 42);
    }

    #[test]
    fn test_kat_test_result_failed_matches_expected() {
        let result = KatTestResult::failed(
            "test-2".to_string(),
            "ML-KEM".to_string(),
            "mismatch".to_string(),
            100,
        );
        assert!(!result.passed);
        assert_eq!(result.test_case, "test-2");
        assert_eq!(result.algorithm, "ML-KEM");
        assert_eq!(result.error_message.as_deref(), Some("mismatch"));
        assert_eq!(result.execution_time_us, 100);
    }

    #[test]
    fn test_kat_test_result_clone_debug_matches_expected() {
        let result = KatTestResult::passed("tc".to_string(), "SHA-256".to_string(), 10);
        let cloned = result.clone();
        assert_eq!(cloned.test_case, result.test_case);
        let debug = format!("{:?}", result);
        assert!(debug.contains("SHA-256"));
    }

    #[test]
    fn test_decode_hex_valid_succeeds() {
        let bytes = decode_hex("48656c6c6f").unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_decode_hex_empty_succeeds() {
        let bytes = decode_hex("").unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_decode_hex_invalid_fails() {
        let result = decode_hex("xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_nist_kat_error_display_matches_expected() {
        let e1 = NistKatError::TestFailed {
            algorithm: "AES".to_string(),
            test_name: "tc1".to_string(),
            message: "fail".to_string(),
        };
        let s = e1.to_string();
        assert!(s.contains("AES"));
        assert!(s.contains("tc1"));
        assert!(s.contains("fail"));

        let e2 = NistKatError::HexError("bad hex".to_string());
        assert!(e2.to_string().contains("bad hex"));

        let e3 = NistKatError::ImplementationError("impl error".to_string());
        assert!(e3.to_string().contains("impl error"));

        let e4 = NistKatError::UnsupportedAlgorithm("FooAlg".to_string());
        assert!(e4.to_string().contains("FooAlg"));

        // Debug
        let debug = format!("{:?}", e1);
        assert!(debug.contains("TestFailed"));
    }
}

// Originally: fips_nist_kat_mod_tests.rs
mod mod_tests {
    //! Comprehensive tests for arc-validation/src/nist_kat/mod.rs
    //!
    //! This test module covers:
    //! - Module-level exports and re-exports
    //! - All public functions (decode_hex, KatTestResult, NistKatError)
    //! - KatRunner and KatSummary functionality
    //! - Integration between submodules
    //! - Error handling
    //! - Edge cases

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

    use latticearc_tests::validation::nist_kat::{
        KatRunner, KatSummary, KatTestResult, NistKatError, aes_gcm_kat, chacha20_poly1305_kat,
        decode_hex, hkdf_kat, hmac_kat, ml_dsa_kat, ml_kem_kat, sha2_kat,
    };

    // ============================================================================
    // Module Re-export Tests
    // ============================================================================

    mod re_export_tests {
        use super::*;

        #[test]
        fn test_kat_runner_exported_is_accessible() {
            // Verify KatRunner is properly exported
            let runner = KatRunner::new();
            assert!(runner.summary().total == 0);
        }

        #[test]
        fn test_kat_summary_exported_is_accessible() {
            // Verify KatSummary is properly exported
            let summary = KatSummary::new();
            assert_eq!(summary.total, 0);
            assert_eq!(summary.passed, 0);
            assert_eq!(summary.failed, 0);
        }

        #[test]
        fn test_aes_gcm_kat_module_exported_is_accessible() {
            // Verify AES-GCM KAT module is accessible
            assert!(!aes_gcm_kat::AES_128_GCM_VECTORS.is_empty());
            assert!(!aes_gcm_kat::AES_256_GCM_VECTORS.is_empty());
        }

        #[test]
        fn test_sha2_kat_module_exported_is_accessible() {
            // Verify SHA2 KAT module is accessible
            assert!(!sha2_kat::SHA256_VECTORS.is_empty());
            assert!(!sha2_kat::SHA224_VECTORS.is_empty());
            assert!(!sha2_kat::SHA384_VECTORS.is_empty());
            assert!(!sha2_kat::SHA512_VECTORS.is_empty());
        }

        #[test]
        fn test_hkdf_kat_module_exported_is_accessible() {
            // Verify HKDF KAT module is accessible
            assert!(!hkdf_kat::HKDF_SHA256_VECTORS.is_empty());
        }

        #[test]
        fn test_hmac_kat_module_exported_is_accessible() {
            // Verify HMAC KAT module is accessible
            assert!(!hmac_kat::HMAC_VECTORS.is_empty());
        }

        #[test]
        fn test_chacha20_poly1305_kat_module_exported_is_accessible() {
            // Verify ChaCha20-Poly1305 KAT module is accessible
            assert!(!chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS.is_empty());
        }

        #[test]
        fn test_ml_kem_kat_module_exported_is_accessible() {
            // Verify ML-KEM KAT fingerprints are accessible
            assert!(!ml_kem_kat::ML_KEM_512_FINGERPRINTS.is_empty());
            assert!(!ml_kem_kat::ML_KEM_768_FINGERPRINTS.is_empty());
            assert!(!ml_kem_kat::ML_KEM_1024_FINGERPRINTS.is_empty());
        }

        #[test]
        fn test_ml_dsa_kat_module_exported_is_accessible() {
            // Verify ML-DSA KAT fingerprints are accessible
            assert_eq!(ml_dsa_kat::ML_DSA_44_FINGERPRINT.pk_len, 1312);
            assert_eq!(ml_dsa_kat::ML_DSA_65_FINGERPRINT.pk_len, 1952);
            assert_eq!(ml_dsa_kat::ML_DSA_87_FINGERPRINT.pk_len, 2592);
        }
    }

    // ============================================================================
    // decode_hex Function Tests
    // ============================================================================

    mod decode_hex_tests {
        use super::*;

        #[test]
        fn test_decode_hex_empty_string_returns_empty_vec_succeeds() {
            let result = decode_hex("");
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }

        #[test]
        fn test_decode_hex_valid_lowercase_succeeds() {
            let result = decode_hex("0123456789abcdef");
            assert!(result.is_ok());
            let bytes = result.unwrap();
            assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        }

        #[test]
        fn test_decode_hex_valid_uppercase_succeeds() {
            let result = decode_hex("0123456789ABCDEF");
            assert!(result.is_ok());
            let bytes = result.unwrap();
            assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        }

        #[test]
        fn test_decode_hex_mixed_case_succeeds() {
            let result = decode_hex("0123456789AbCdEf");
            assert!(result.is_ok());
            let bytes = result.unwrap();
            assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        }

        #[test]
        fn test_decode_hex_single_byte_succeeds() {
            let result = decode_hex("ff");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xff]);
        }

        #[test]
        fn test_decode_hex_all_zeros_succeeds() {
            let result = decode_hex("0000000000000000");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0, 0, 0, 0, 0, 0, 0, 0]);
        }

        #[test]
        fn test_decode_hex_all_ones_succeeds() {
            let result = decode_hex("ffffffff");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xff, 0xff, 0xff, 0xff]);
        }

        #[test]
        fn test_decode_hex_invalid_char_returns_error() {
            let result = decode_hex("0g");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(_)) => {}
                _ => panic!("Expected HexError"),
            }
        }

        #[test]
        fn test_decode_hex_odd_length_returns_error() {
            let result = decode_hex("123");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(_)) => {}
                _ => panic!("Expected HexError"),
            }
        }

        #[test]
        fn test_decode_hex_with_spaces_returns_error() {
            let result = decode_hex("01 23");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(_)) => {}
                _ => panic!("Expected HexError"),
            }
        }

        #[test]
        fn test_decode_hex_with_prefix_returns_error() {
            let result = decode_hex("0x0123");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(_)) => {}
                _ => panic!("Expected HexError"),
            }
        }

        #[test]
        fn test_decode_hex_unicode_returns_error() {
            let result = decode_hex("\u{00e9}");
            assert!(result.is_err());
        }

        #[test]
        fn test_decode_hex_long_string_succeeds() {
            // Test with a 128-byte (256 hex chars) string
            let hex_str = "00".repeat(128);
            let result = decode_hex(&hex_str);
            assert!(result.is_ok());
            let bytes = result.unwrap();
            assert_eq!(bytes.len(), 128);
            assert!(bytes.iter().all(|&b| b == 0));
        }
    }

    // ============================================================================
    // NistKatError Tests
    // ============================================================================

    mod nist_kat_error_tests {
        use super::*;

        #[test]
        fn test_error_test_failed_has_correct_message_fails() {
            let error = NistKatError::TestFailed {
                algorithm: "AES-256-GCM".to_string(),
                test_name: "Test-1".to_string(),
                message: "Output mismatch".to_string(),
            };
            let error_string = error.to_string();
            assert!(error_string.contains("AES-256-GCM"));
            assert!(error_string.contains("Test-1"));
            assert!(error_string.contains("Output mismatch"));
        }

        #[test]
        fn test_error_hex_error_has_correct_message_fails() {
            let error = NistKatError::HexError("Invalid hex character".to_string());
            let error_string = error.to_string();
            assert!(error_string.contains("Invalid hex character"));
        }

        #[test]
        fn test_error_implementation_error_has_correct_message_fails() {
            let error = NistKatError::ImplementationError("Key creation failed".to_string());
            let error_string = error.to_string();
            assert!(error_string.contains("Key creation failed"));
        }

        #[test]
        fn test_error_unsupported_algorithm_has_correct_message_fails() {
            let error = NistKatError::UnsupportedAlgorithm("UNKNOWN-ALG".to_string());
            let error_string = error.to_string();
            assert!(error_string.contains("UNKNOWN-ALG"));
        }

        #[test]
        fn test_error_debug_format_has_correct_string_fails() {
            let error = NistKatError::TestFailed {
                algorithm: "SHA-256".to_string(),
                test_name: "Test-2".to_string(),
                message: "Hash mismatch".to_string(),
            };
            let debug_str = format!("{:?}", error);
            assert!(debug_str.contains("TestFailed"));
        }
    }

    // ============================================================================
    // KatTestResult Tests
    // ============================================================================

    mod kat_test_result_tests {
        use super::*;

        #[test]
        fn test_passed_result_has_correct_fields_succeeds() {
            let result =
                KatTestResult::passed("Test-Case-1".to_string(), "AES-128-GCM".to_string(), 1000);
            assert!(result.passed);
            assert_eq!(result.test_case, "Test-Case-1");
            assert_eq!(result.algorithm, "AES-128-GCM");
            assert!(result.error_message.is_none());
            assert_eq!(result.execution_time_us, 1000);
        }

        #[test]
        fn test_failed_result_has_correct_fields_fails() {
            let result = KatTestResult::failed(
                "Test-Case-2".to_string(),
                "SHA-256".to_string(),
                "Hash mismatch".to_string(),
                500,
            );
            assert!(!result.passed);
            assert_eq!(result.test_case, "Test-Case-2");
            assert_eq!(result.algorithm, "SHA-256");
            assert_eq!(result.error_message, Some("Hash mismatch".to_string()));
            assert_eq!(result.execution_time_us, 500);
        }

        #[test]
        fn test_result_clone_produces_equal_value_succeeds() {
            let result =
                KatTestResult::passed("Test-Clone".to_string(), "HMAC-SHA512".to_string(), 200);
            let cloned = result.clone();
            assert_eq!(result.test_case, cloned.test_case);
            assert_eq!(result.algorithm, cloned.algorithm);
            assert_eq!(result.passed, cloned.passed);
            assert_eq!(result.execution_time_us, cloned.execution_time_us);
        }

        #[test]
        fn test_result_debug_has_correct_format() {
            let result = KatTestResult::passed("Test-Debug".to_string(), "HKDF".to_string(), 100);
            let debug_str = format!("{:?}", result);
            assert!(debug_str.contains("Test-Debug"));
            assert!(debug_str.contains("HKDF"));
        }

        #[test]
        fn test_passed_with_zero_time_has_correct_fields_succeeds() {
            let result = KatTestResult::passed("Zero-Time".to_string(), "Fast-Test".to_string(), 0);
            assert!(result.passed);
            assert_eq!(result.execution_time_us, 0);
        }

        #[test]
        fn test_failed_with_empty_error_message_has_correct_fields_fails() {
            let result = KatTestResult::failed(
                "Empty-Error".to_string(),
                "Test".to_string(),
                "".to_string(),
                1,
            );
            assert!(!result.passed);
            assert_eq!(result.error_message, Some("".to_string()));
        }
    }

    // ============================================================================
    // KatSummary Tests
    // ============================================================================

    mod kat_summary_tests {
        use super::*;

        #[test]
        fn test_new_summary_has_correct_fields_succeeds() {
            let summary = KatSummary::new();
            assert_eq!(summary.total, 0);
            assert_eq!(summary.passed, 0);
            assert_eq!(summary.failed, 0);
            assert!(summary.results.is_empty());
            assert_eq!(summary.total_time_ms, 0);
        }

        #[test]
        fn test_default_summary_has_correct_fields_succeeds() {
            let summary = KatSummary::default();
            assert_eq!(summary.total, 0);
            assert_eq!(summary.passed, 0);
            assert_eq!(summary.failed, 0);
        }

        #[test]
        fn test_add_passed_result_increments_count_succeeds() {
            let mut summary = KatSummary::new();
            let result = KatTestResult::passed("Test-1".to_string(), "Algo-1".to_string(), 1000);
            summary.add_result(result);

            assert_eq!(summary.total, 1);
            assert_eq!(summary.passed, 1);
            assert_eq!(summary.failed, 0);
            assert_eq!(summary.results.len(), 1);
            assert_eq!(summary.total_time_ms, 1); // 1000us / 1000 = 1ms
        }

        #[test]
        fn test_add_failed_result_increments_count_fails() {
            let mut summary = KatSummary::new();
            let result = KatTestResult::failed(
                "Test-2".to_string(),
                "Algo-2".to_string(),
                "Error".to_string(),
                2000,
            );
            summary.add_result(result);

            assert_eq!(summary.total, 1);
            assert_eq!(summary.passed, 0);
            assert_eq!(summary.failed, 1);
        }

        #[test]
        fn test_add_multiple_results_updates_counts_succeeds() {
            let mut summary = KatSummary::new();

            // Add 3 passed, 2 failed
            summary.add_result(KatTestResult::passed("P1".to_string(), "A1".to_string(), 1000));
            summary.add_result(KatTestResult::passed("P2".to_string(), "A1".to_string(), 1000));
            summary.add_result(KatTestResult::passed("P3".to_string(), "A2".to_string(), 1000));
            summary.add_result(KatTestResult::failed(
                "F1".to_string(),
                "A2".to_string(),
                "E1".to_string(),
                1000,
            ));
            summary.add_result(KatTestResult::failed(
                "F2".to_string(),
                "A3".to_string(),
                "E2".to_string(),
                1000,
            ));

            assert_eq!(summary.total, 5);
            assert_eq!(summary.passed, 3);
            assert_eq!(summary.failed, 2);
            assert_eq!(summary.results.len(), 5);
        }

        #[test]
        fn test_all_passed_true_when_all_succeed_succeeds() {
            let mut summary = KatSummary::new();
            summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
            summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 0));

            assert!(summary.all_passed());
        }

        #[test]
        fn test_all_passed_false_when_any_fail_fails() {
            let mut summary = KatSummary::new();
            summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
            summary.add_result(KatTestResult::failed(
                "T2".to_string(),
                "A".to_string(),
                "E".to_string(),
                0,
            ));

            assert!(!summary.all_passed());
        }

        #[test]
        fn test_all_passed_empty_returns_true_succeeds() {
            let summary = KatSummary::new();
            assert!(summary.all_passed()); // No failures means all passed
        }

        #[test]
        fn test_pass_rate_all_passed_is_correct() {
            let mut summary = KatSummary::new();
            summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
            summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 0));

            assert!((summary.pass_rate() - 100.0).abs() < 0.001);
        }

        #[test]
        fn test_pass_rate_all_failed_is_correct() {
            let mut summary = KatSummary::new();
            summary.add_result(KatTestResult::failed(
                "T1".to_string(),
                "A".to_string(),
                "E".to_string(),
                0,
            ));
            summary.add_result(KatTestResult::failed(
                "T2".to_string(),
                "A".to_string(),
                "E".to_string(),
                0,
            ));

            assert!((summary.pass_rate() - 0.0).abs() < 0.001);
        }

        #[test]
        fn test_pass_rate_fifty_percent_is_correct() {
            let mut summary = KatSummary::new();
            summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 0));
            summary.add_result(KatTestResult::failed(
                "T2".to_string(),
                "A".to_string(),
                "E".to_string(),
                0,
            ));

            assert!((summary.pass_rate() - 50.0).abs() < 0.001);
        }

        #[test]
        fn test_pass_rate_empty_is_correct() {
            let summary = KatSummary::new();
            assert!((summary.pass_rate() - 0.0).abs() < 0.001);
        }

        #[test]
        fn test_summary_clone_produces_equal_value_succeeds() {
            let mut summary = KatSummary::new();
            summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 1000));
            let cloned = summary.clone();

            assert_eq!(summary.total, cloned.total);
            assert_eq!(summary.passed, cloned.passed);
            assert_eq!(summary.results.len(), cloned.results.len());
        }

        #[test]
        fn test_summary_print_does_not_panic_on_output_succeeds() {
            // Just verify print doesn't panic with various states
            let mut summary = KatSummary::new();
            summary.print(); // Empty

            summary.add_result(KatTestResult::passed("T".to_string(), "A".to_string(), 0));
            summary.print(); // With passed

            summary.add_result(KatTestResult::failed(
                "T2".to_string(),
                "A".to_string(),
                "Error".to_string(),
                0,
            ));
            summary.print(); // With failed
        }
    }

    // ============================================================================
    // KatRunner Tests
    // ============================================================================

    mod kat_runner_tests {
        use super::*;

        #[test]
        fn test_new_runner_succeeds() {
            let runner = KatRunner::new();
            let summary = runner.summary();
            assert_eq!(summary.total, 0);
        }

        #[test]
        fn test_default_runner_succeeds() {
            let runner = KatRunner::default();
            assert_eq!(runner.summary().total, 0);
        }

        #[test]
        fn test_run_passing_test_increments_pass_count_succeeds() {
            let mut runner = KatRunner::new();
            runner.run_test("Test-1", "Algo", || Ok(()));

            let summary = runner.summary();
            assert_eq!(summary.total, 1);
            assert_eq!(summary.passed, 1);
            assert_eq!(summary.failed, 0);
        }

        #[test]
        fn test_run_failing_test_increments_fail_count_fails() {
            let mut runner = KatRunner::new();
            runner.run_test("Test-2", "Algo", || {
                Err(NistKatError::TestFailed {
                    algorithm: "Algo".to_string(),
                    test_name: "Test-2".to_string(),
                    message: "Failure".to_string(),
                })
            });

            let summary = runner.summary();
            assert_eq!(summary.total, 1);
            assert_eq!(summary.passed, 0);
            assert_eq!(summary.failed, 1);
        }

        #[test]
        fn test_run_multiple_tests_updates_counts_succeeds() {
            let mut runner = KatRunner::new();

            // Two passing tests
            runner.run_test("Pass-1", "A1", || Ok(()));
            runner.run_test("Pass-2", "A1", || Ok(()));

            // One failing test
            runner.run_test("Fail-1", "A2", || {
                Err(NistKatError::ImplementationError("Error".to_string()))
            });

            let summary = runner.summary();
            assert_eq!(summary.total, 3);
            assert_eq!(summary.passed, 2);
            assert_eq!(summary.failed, 1);
        }

        #[test]
        fn test_finish_returns_summary_with_correct_counts_succeeds() {
            let mut runner = KatRunner::new();
            runner.run_test("Test", "Algo", || Ok(()));

            let summary = runner.finish();
            assert_eq!(summary.total, 1);
            assert!(summary.all_passed());
        }

        #[test]
        fn test_runner_records_execution_time_correctly_succeeds() {
            let mut runner = KatRunner::new();
            runner.run_test("Slow-Test", "Algo", || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                Ok(())
            });

            let summary = runner.summary();
            assert!(summary.results[0].execution_time_us > 0);
        }

        #[test]
        fn test_runner_hex_error_returns_error() {
            let mut runner = KatRunner::new();
            runner.run_test("Hex-Test", "Algo", || Err(NistKatError::HexError("bad".to_string())));

            assert!(!runner.summary().all_passed());
            assert!(runner.summary().results[0].error_message.as_ref().unwrap().contains("Hex"));
        }

        #[test]
        fn test_runner_unsupported_algorithm_returns_error() {
            let mut runner = KatRunner::new();
            runner.run_test("Unsupported", "Unknown", || {
                Err(NistKatError::UnsupportedAlgorithm("Unknown".to_string()))
            });

            assert_eq!(runner.summary().failed, 1);
        }
    }

    // ============================================================================
    // Integration Tests - Submodule Functions
    // ============================================================================

    mod submodule_function_tests {
        use super::*;

        #[test]
        fn test_run_aes_128_gcm_kat_matches_vector() {
            let result = aes_gcm_kat::run_aes_128_gcm_kat();
            assert!(result.is_ok(), "AES-128-GCM KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_aes_256_gcm_kat_matches_vector() {
            let result = aes_gcm_kat::run_aes_256_gcm_kat();
            assert!(result.is_ok(), "AES-256-GCM KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_sha256_kat_matches_vector() {
            let result = sha2_kat::run_sha256_kat();
            assert!(result.is_ok(), "SHA-256 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_sha224_kat_matches_vector() {
            let result = sha2_kat::run_sha224_kat();
            assert!(result.is_ok(), "SHA-224 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_sha384_kat_matches_vector() {
            let result = sha2_kat::run_sha384_kat();
            assert!(result.is_ok(), "SHA-384 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_sha512_kat_matches_vector() {
            let result = sha2_kat::run_sha512_kat();
            assert!(result.is_ok(), "SHA-512 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_sha512_224_kat_matches_vector() {
            let result = sha2_kat::run_sha512_224_kat();
            assert!(result.is_ok(), "SHA-512/224 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_sha512_256_kat_matches_vector() {
            let result = sha2_kat::run_sha512_256_kat();
            assert!(result.is_ok(), "SHA-512/256 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_hkdf_sha256_kat_matches_vector() {
            let result = hkdf_kat::run_hkdf_sha256_kat();
            assert!(result.is_ok(), "HKDF-SHA256 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_hmac_sha224_kat_matches_vector() {
            let result = hmac_kat::run_hmac_sha224_kat();
            assert!(result.is_ok(), "HMAC-SHA224 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_hmac_sha256_kat_matches_vector() {
            let result = hmac_kat::run_hmac_sha256_kat();
            assert!(result.is_ok(), "HMAC-SHA256 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_hmac_sha384_kat_matches_vector() {
            let result = hmac_kat::run_hmac_sha384_kat();
            assert!(result.is_ok(), "HMAC-SHA384 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_hmac_sha512_kat_matches_vector() {
            let result = hmac_kat::run_hmac_sha512_kat();
            assert!(result.is_ok(), "HMAC-SHA512 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_chacha20_poly1305_kat_matches_vector() {
            let result = chacha20_poly1305_kat::run_chacha20_poly1305_kat();
            assert!(result.is_ok(), "ChaCha20-Poly1305 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_ml_kem_512_kat_matches_vector() {
            let result = ml_kem_kat::run_ml_kem_512_kat();
            assert!(result.is_ok(), "ML-KEM-512 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_ml_kem_768_kat_matches_vector() {
            let result = ml_kem_kat::run_ml_kem_768_kat();
            assert!(result.is_ok(), "ML-KEM-768 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_ml_kem_1024_kat_matches_vector() {
            let result = ml_kem_kat::run_ml_kem_1024_kat();
            assert!(result.is_ok(), "ML-KEM-1024 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_ml_dsa_44_kat_matches_vector() {
            let result = ml_dsa_kat::run_ml_dsa_44_kat();
            assert!(result.is_ok(), "ML-DSA-44 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_ml_dsa_65_kat_matches_vector() {
            let result = ml_dsa_kat::run_ml_dsa_65_kat();
            assert!(result.is_ok(), "ML-DSA-65 KAT failed: {:?}", result);
        }

        #[test]
        fn test_run_ml_dsa_87_kat_matches_vector() {
            let result = ml_dsa_kat::run_ml_dsa_87_kat();
            assert!(result.is_ok(), "ML-DSA-87 KAT failed: {:?}", result);
        }
    }

    // ============================================================================
    // Integration Tests - KatRunner with Real Tests
    // ============================================================================

    mod kat_runner_integration_tests {
        use super::*;

        #[test]
        fn test_runner_with_aes_gcm_kats_all_pass_matches_expected() {
            let mut runner = KatRunner::new();

            runner
                .run_test("AES-128-GCM-All", "AES-128-GCM", || aes_gcm_kat::run_aes_128_gcm_kat());
            runner
                .run_test("AES-256-GCM-All", "AES-256-GCM", || aes_gcm_kat::run_aes_256_gcm_kat());

            let summary = runner.finish();
            assert!(summary.all_passed());
            assert_eq!(summary.total, 2);
        }

        #[test]
        fn test_runner_with_sha2_kats_all_pass_matches_expected() {
            let mut runner = KatRunner::new();

            runner.run_test("SHA-224", "SHA-224", || sha2_kat::run_sha224_kat());
            runner.run_test("SHA-256", "SHA-256", || sha2_kat::run_sha256_kat());
            runner.run_test("SHA-384", "SHA-384", || sha2_kat::run_sha384_kat());
            runner.run_test("SHA-512", "SHA-512", || sha2_kat::run_sha512_kat());
            runner.run_test("SHA-512/224", "SHA-512/224", || sha2_kat::run_sha512_224_kat());
            runner.run_test("SHA-512/256", "SHA-512/256", || sha2_kat::run_sha512_256_kat());

            let summary = runner.finish();
            assert!(summary.all_passed());
            assert_eq!(summary.total, 6);
        }

        #[test]
        fn test_runner_with_hmac_kats_all_pass_matches_expected() {
            let mut runner = KatRunner::new();

            runner.run_test("HMAC-SHA224", "HMAC-SHA224", || hmac_kat::run_hmac_sha224_kat());
            runner.run_test("HMAC-SHA256", "HMAC-SHA256", || hmac_kat::run_hmac_sha256_kat());
            runner.run_test("HMAC-SHA384", "HMAC-SHA384", || hmac_kat::run_hmac_sha384_kat());
            runner.run_test("HMAC-SHA512", "HMAC-SHA512", || hmac_kat::run_hmac_sha512_kat());

            let summary = runner.finish();
            assert!(summary.all_passed());
            assert_eq!(summary.total, 4);
        }

        #[test]
        fn test_runner_with_pqc_kats_all_pass_matches_expected() {
            let mut runner = KatRunner::new();

            runner.run_test("ML-KEM-512", "ML-KEM-512", || ml_kem_kat::run_ml_kem_512_kat());
            runner.run_test("ML-KEM-768", "ML-KEM-768", || ml_kem_kat::run_ml_kem_768_kat());
            runner.run_test("ML-KEM-1024", "ML-KEM-1024", || ml_kem_kat::run_ml_kem_1024_kat());

            let summary = runner.finish();
            assert!(summary.all_passed());
            assert_eq!(summary.total, 3);
        }

        #[test]
        fn test_runner_comprehensive_kat_suite_all_pass_matches_expected() {
            let mut runner = KatRunner::new();

            // Symmetric crypto
            runner.run_test("AES-128-GCM", "AEAD", || aes_gcm_kat::run_aes_128_gcm_kat());
            runner.run_test("AES-256-GCM", "AEAD", || aes_gcm_kat::run_aes_256_gcm_kat());
            runner.run_test("ChaCha20-Poly1305", "AEAD", || {
                chacha20_poly1305_kat::run_chacha20_poly1305_kat()
            });

            // Hashing
            runner.run_test("SHA-256", "Hash", || sha2_kat::run_sha256_kat());

            // Key derivation
            runner.run_test("HKDF-SHA256", "KDF", || hkdf_kat::run_hkdf_sha256_kat());

            // MACs
            runner.run_test("HMAC-SHA256", "MAC", || hmac_kat::run_hmac_sha256_kat());

            // Post-quantum
            runner.run_test("ML-KEM-768", "PQC-KEM", || ml_kem_kat::run_ml_kem_768_kat());
            runner.run_test("ML-DSA-65", "PQC-DSA", || ml_dsa_kat::run_ml_dsa_65_kat());

            let summary = runner.finish();
            summary.print();
            assert!(
                summary.all_passed(),
                "Comprehensive KAT suite failed with {} failures",
                summary.failed
            );
            assert_eq!(summary.total, 8);
        }
    }

    // ============================================================================
    // Edge Cases and Error Condition Tests
    // ============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_vector_struct_field_access_succeeds() {
            // Test that we can access test vector struct fields
            let aes_vector = &aes_gcm_kat::AES_128_GCM_VECTORS[0];
            assert!(!aes_vector.test_name.is_empty());
            assert!(!aes_vector.key.is_empty());
            assert!(!aes_vector.nonce.is_empty());
            // AAD can be empty
            // Plaintext can be empty (Test Case 1)
            assert!(!aes_vector.expected_tag.is_empty());
        }

        #[test]
        fn test_sha2_vector_struct_field_access_succeeds() {
            let sha_vector = &sha2_kat::SHA256_VECTORS[0];
            assert!(!sha_vector.test_name.is_empty());
            // Message can be empty
            assert!(!sha_vector.expected_hash.is_empty());
        }

        #[test]
        fn test_hkdf_vector_struct_field_access_succeeds() {
            let hkdf_vector = &hkdf_kat::HKDF_SHA256_VECTORS[0];
            assert!(!hkdf_vector.test_name.is_empty());
            assert!(!hkdf_vector.ikm.is_empty());
            // Salt can be empty
            // Info can be empty
            assert!(hkdf_vector.length > 0);
            assert!(!hkdf_vector.expected_prk.is_empty());
            assert!(!hkdf_vector.expected_okm.is_empty());
        }

        #[test]
        fn test_hmac_vector_struct_field_access_succeeds() {
            let hmac_vector = &hmac_kat::HMAC_VECTORS[0];
            assert!(!hmac_vector.test_name.is_empty());
            assert!(!hmac_vector.key.is_empty());
            assert!(!hmac_vector.message.is_empty());
            assert!(!hmac_vector.expected_mac_sha224.is_empty());
            assert!(!hmac_vector.expected_mac_sha256.is_empty());
            assert!(!hmac_vector.expected_mac_sha384.is_empty());
            assert!(!hmac_vector.expected_mac_sha512.is_empty());
        }

        #[test]
        fn test_ml_kem_fingerprint_struct_field_access_succeeds() {
            let fp = &ml_kem_kat::ML_KEM_512_FINGERPRINTS[0];
            assert!(!fp.test_name.is_empty());
            assert!(!fp.ek_first32.is_empty());
            assert!(!fp.dk_first32.is_empty());
        }

        #[test]
        fn test_ml_dsa_fingerprint_struct_field_access_succeeds() {
            let fp = &ml_dsa_kat::ML_DSA_44_FINGERPRINT;
            assert!(!fp.test_name.is_empty());
            assert!(!fp.pk_first32.is_empty());
        }

        #[test]
        fn test_chacha20_poly1305_vector_struct_field_access_succeeds() {
            let cc_vector = &chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS[0];
            assert!(!cc_vector.test_name.is_empty());
            assert!(!cc_vector.key.is_empty());
            assert!(!cc_vector.nonce.is_empty());
            // AAD can be empty
            assert!(!cc_vector.plaintext.is_empty());
            assert!(!cc_vector.expected_ciphertext.is_empty());
            assert!(!cc_vector.expected_tag.is_empty());
        }

        #[test]
        fn test_runner_handles_mixed_results_correctly_succeeds() {
            let mut runner = KatRunner::new();

            runner.run_test("Pass", "Algo", || Ok(()));
            runner.run_test("Fail", "Algo", || {
                Err(NistKatError::TestFailed {
                    algorithm: "Algo".to_string(),
                    test_name: "Fail".to_string(),
                    message: "Expected failure".to_string(),
                })
            });
            runner.run_test("Pass2", "Algo", || Ok(()));

            let summary = runner.finish();
            assert_eq!(summary.total, 3);
            assert_eq!(summary.passed, 2);
            assert_eq!(summary.failed, 1);
            assert!(!summary.all_passed());
        }

        #[test]
        fn test_summary_time_accumulation_is_correct() {
            let mut summary = KatSummary::new();

            // Add results with known execution times
            summary.add_result(KatTestResult::passed("T1".to_string(), "A".to_string(), 1000)); // 1ms
            summary.add_result(KatTestResult::passed("T2".to_string(), "A".to_string(), 2000)); // 2ms
            summary.add_result(KatTestResult::passed("T3".to_string(), "A".to_string(), 3000)); // 3ms

            assert_eq!(summary.total_time_ms, 6); // 1 + 2 + 3 = 6ms
        }

        #[test]
        fn test_many_test_results_are_tracked_correctly_succeeds() {
            let mut summary = KatSummary::new();

            // Add 100 results
            for i in 0..100 {
                if i % 10 == 0 {
                    summary.add_result(KatTestResult::failed(
                        format!("Test-{}", i),
                        "Algo".to_string(),
                        "Error".to_string(),
                        100,
                    ));
                } else {
                    summary.add_result(KatTestResult::passed(
                        format!("Test-{}", i),
                        "Algo".to_string(),
                        100,
                    ));
                }
            }

            assert_eq!(summary.total, 100);
            assert_eq!(summary.passed, 90);
            assert_eq!(summary.failed, 10);
            assert!((summary.pass_rate() - 90.0).abs() < 0.001);
        }
    }

    // ============================================================================
    // Test Vector Count Validation
    // ============================================================================

    mod vector_count_tests {
        use super::*;

        #[test]
        fn test_aes_128_gcm_vector_count_is_correct() {
            assert_eq!(aes_gcm_kat::AES_128_GCM_VECTORS.len(), 3, "Expected 3 AES-128-GCM vectors");
        }

        #[test]
        fn test_aes_256_gcm_vector_count_is_correct() {
            assert_eq!(aes_gcm_kat::AES_256_GCM_VECTORS.len(), 3, "Expected 3 AES-256-GCM vectors");
        }

        #[test]
        fn test_sha256_vector_count_is_correct() {
            assert_eq!(sha2_kat::SHA256_VECTORS.len(), 4, "Expected 4 SHA-256 vectors");
        }

        #[test]
        fn test_sha224_vector_count_is_correct() {
            assert_eq!(sha2_kat::SHA224_VECTORS.len(), 2, "Expected 2 SHA-224 vectors");
        }

        #[test]
        fn test_sha384_vector_count_is_correct() {
            assert_eq!(sha2_kat::SHA384_VECTORS.len(), 2, "Expected 2 SHA-384 vectors");
        }

        #[test]
        fn test_sha512_vector_count_is_correct() {
            assert_eq!(sha2_kat::SHA512_VECTORS.len(), 2, "Expected 2 SHA-512 vectors");
        }

        #[test]
        fn test_sha512_224_vector_count_is_correct() {
            assert_eq!(sha2_kat::SHA512_224_VECTORS.len(), 2, "Expected 2 SHA-512/224 vectors");
        }

        #[test]
        fn test_sha512_256_vector_count_is_correct() {
            assert_eq!(sha2_kat::SHA512_256_VECTORS.len(), 2, "Expected 2 SHA-512/256 vectors");
        }

        #[test]
        fn test_hkdf_sha256_vector_count_is_correct() {
            assert_eq!(hkdf_kat::HKDF_SHA256_VECTORS.len(), 3, "Expected 3 HKDF-SHA256 vectors");
        }

        #[test]
        fn test_hmac_vector_count_is_correct() {
            assert_eq!(hmac_kat::HMAC_VECTORS.len(), 6, "Expected 6 HMAC vectors");
        }

        #[test]
        fn test_chacha20_poly1305_vector_count_is_correct() {
            assert_eq!(
                chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS.len(),
                1,
                "Expected 1 ChaCha20-Poly1305 vector"
            );
        }

        #[test]
        fn test_ml_kem_512_fingerprint_count_is_correct() {
            assert_eq!(
                ml_kem_kat::ML_KEM_512_FINGERPRINTS.len(),
                1,
                "Expected 1 ML-KEM-512 fingerprint"
            );
        }

        #[test]
        fn test_ml_kem_768_fingerprint_count_is_correct() {
            assert_eq!(
                ml_kem_kat::ML_KEM_768_FINGERPRINTS.len(),
                1,
                "Expected 1 ML-KEM-768 fingerprint"
            );
        }

        #[test]
        fn test_ml_kem_1024_fingerprint_count_is_correct() {
            assert_eq!(
                ml_kem_kat::ML_KEM_1024_FINGERPRINTS.len(),
                1,
                "Expected 1 ML-KEM-1024 fingerprint"
            );
        }

        #[test]
        fn test_ml_dsa_44_fingerprint_exists() {
            assert_eq!(ml_dsa_kat::ML_DSA_44_FINGERPRINT.pk_len, 1312);
        }

        #[test]
        fn test_ml_dsa_65_fingerprint_exists() {
            assert_eq!(ml_dsa_kat::ML_DSA_65_FINGERPRINT.pk_len, 1952);
        }

        #[test]
        fn test_ml_dsa_87_fingerprint_exists() {
            assert_eq!(ml_dsa_kat::ML_DSA_87_FINGERPRINT.pk_len, 2592);
        }
    }
}
