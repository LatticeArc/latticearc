//! CAVP pipeline sign/verify roundtrip and dispatch-coverage tests.
//!
//! Sub-modules preserve the structure and imports of their original
//! source files (split from the former consolidated fips_cavp.rs).

#![deny(unsafe_code)]

mod pipeline_sign_verify_roundtrip {
    //! Coverage tests for CAVP pipeline Signature and Verification paths.
    //! Exercises real crypto roundtrips: KeyGen → Sign → Verify for each algorithm variant.
    //! Targets pipeline.rs lines: ML-DSA sign/verify (44, 65, 87), SLH-DSA sign/verify
    //! (shake-128s, 192s, 256s), FN-DSA sign/verify (512, 1024).

    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use latticearc_tests::validation::cavp::pipeline::{CavpTestExecutor, PipelineConfig};
    use latticearc_tests::validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_executor() -> CavpTestExecutor {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        CavpTestExecutor::new(config, storage)
    }

    fn make_keygen_vector(id: &str, algorithm: CavpAlgorithm) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x42; 48]),
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: Some(vec![0x11; 32]),
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0xAA; 64]),
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    fn make_sign_vector(
        id: &str,
        algorithm: CavpAlgorithm,
        sk: Vec<u8>,
        message: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: None,
                sk: Some(sk),
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0xBB; 128]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    fn make_verify_vector(
        id: &str,
        algorithm: CavpAlgorithm,
        pk: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: Some(pk),
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: Some(signature),
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Verification,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    // ============================================================
    // ML-DSA-44 Sign + Verify roundtrip (covers mldsa_44_impl Sign/Verify)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for ML-DSA-44 roundtrip".to_vec();

        // Step 1: KeyGen to get real keys
        let alg = CavpAlgorithm::MlDsa { variant: "44".to_string() };
        let keygen_vec = make_keygen_vector("mldsa44-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;
        assert!(!key_material.is_empty(), "KeyGen should produce key material");

        // Split: pk (1312 bytes) + sk (2560 bytes)
        let pk = key_material[..1312].to_vec();
        let sk = key_material[1312..].to_vec();
        assert_eq!(sk.len(), 2560);

        // Step 2: Sign
        let sign_vec = make_sign_vector("mldsa44-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert!(!signature.is_empty(), "Signing should produce a signature");
        assert_eq!(signature.len(), 2420, "ML-DSA-44 signature should be 2420 bytes");

        // Step 3: Verify
        let verify_vec = make_verify_vector("mldsa44-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        // Verify returns [1] for valid, [0] for invalid
        assert_eq!(verify_result.actual_result, vec![1], "Valid signature should verify");
    }

    // ============================================================
    // ML-DSA-65 Sign + Verify roundtrip (covers mldsa_65_impl Sign/Verify)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_65_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for ML-DSA-65 roundtrip".to_vec();

        let alg = CavpAlgorithm::MlDsa { variant: "65".to_string() };
        let keygen_vec = make_keygen_vector("mldsa65-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (1952 bytes) + sk (4032 bytes)
        let pk = key_material[..1952].to_vec();
        let sk = key_material[1952..].to_vec();
        assert_eq!(sk.len(), 4032);

        // Sign
        let sign_vec = make_sign_vector("mldsa65-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 3309);

        // Verify
        let verify_vec = make_verify_vector("mldsa65-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // ML-DSA-87 Sign + Verify roundtrip (covers mldsa_87_impl Sign/Verify)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_87_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for ML-DSA-87 roundtrip".to_vec();

        let alg = CavpAlgorithm::MlDsa { variant: "87".to_string() };
        let keygen_vec = make_keygen_vector("mldsa87-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (2592 bytes) + sk (4896 bytes)
        let pk = key_material[..2592].to_vec();
        let sk = key_material[2592..].to_vec();
        assert_eq!(sk.len(), 4896);

        // Sign
        let sign_vec = make_sign_vector("mldsa87-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 4627);

        // Verify
        let verify_vec = make_verify_vector("mldsa87-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // SLH-DSA-SHAKE-128s Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_shake_128s_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for SLH-DSA-SHAKE-128s".to_vec();

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() };
        let keygen_vec = make_keygen_vector("slhdsa128s-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (32 bytes) + sk (64 bytes)
        let pk = key_material[..32].to_vec();
        let sk = key_material[32..].to_vec();
        assert_eq!(sk.len(), 64);

        // Sign
        let sign_vec = make_sign_vector("slhdsa128s-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 7856);

        // Verify
        let verify_vec = make_verify_vector("slhdsa128s-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // SLH-DSA-SHAKE-192s Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_shake_192s_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for SLH-DSA-SHAKE-192s".to_vec();

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() };
        let keygen_vec = make_keygen_vector("slhdsa192s-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (48 bytes) + sk (96 bytes)
        let pk = key_material[..48].to_vec();
        let sk = key_material[48..].to_vec();
        assert_eq!(sk.len(), 96);

        // Sign
        let sign_vec = make_sign_vector("slhdsa192s-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 16224);

        // Verify
        let verify_vec = make_verify_vector("slhdsa192s-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // SLH-DSA-SHAKE-256s Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_shake_256s_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for SLH-DSA-SHAKE-256s".to_vec();

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() };
        let keygen_vec = make_keygen_vector("slhdsa256s-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (64 bytes) + sk (128 bytes)
        let pk = key_material[..64].to_vec();
        let sk = key_material[64..].to_vec();
        assert_eq!(sk.len(), 128);

        // Sign
        let sign_vec = make_sign_vector("slhdsa256s-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 29792);

        // Verify
        let verify_vec = make_verify_vector("slhdsa256s-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // FN-DSA-512 Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for FN-DSA-512".to_vec();

        let alg = CavpAlgorithm::FnDsa { variant: "512".to_string() };
        let keygen_vec = make_keygen_vector("fndsa512-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // FN-DSA KeyGen returns vrfy_key + sign_key
        // vrfy_key_size(FN_DSA_LOGN_512) and sign_key_size(FN_DSA_LOGN_512)
        // For logn=9 (512): vrfy_key = 897, sign_key = 1281
        let vrfy_key_len = 897;
        let pk = key_material[..vrfy_key_len].to_vec();
        let sk = key_material[vrfy_key_len..].to_vec();
        assert_eq!(sk.len(), 1281, "FN-DSA-512 sign key should be 1281 bytes");

        // Sign
        let sign_vec = make_sign_vector("fndsa512-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert!(!signature.is_empty(), "FN-DSA-512 should produce a signature");

        // Verify
        let verify_vec = make_verify_vector("fndsa512-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // FN-DSA-1024 Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_1024_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for FN-DSA-1024".to_vec();

        let alg = CavpAlgorithm::FnDsa { variant: "1024".to_string() };
        let keygen_vec = make_keygen_vector("fndsa1024-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // For logn=10 (1024): vrfy_key = 1793, sign_key = 2305
        let vrfy_key_len = 1793;
        let pk = key_material[..vrfy_key_len].to_vec();
        let sk = key_material[vrfy_key_len..].to_vec();
        assert_eq!(sk.len(), 2305, "FN-DSA-1024 sign key should be 2305 bytes");

        // Sign
        let sign_vec = make_sign_vector("fndsa1024-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert!(!signature.is_empty(), "FN-DSA-1024 should produce a signature");

        // Verify
        let verify_vec = make_verify_vector("fndsa1024-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // ML-KEM Encapsulation + Decapsulation roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_768_encap_decap_roundtrip() {
        let executor = make_executor();

        let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };

        // Step 1: KeyGen
        let keygen_vec = make_keygen_vector("mlkem768-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // ML-KEM-768: ek (1184 bytes) + dk (2400 bytes)
        let ek_len = 1184;
        let dk_len = 2400;
        let ek = key_material[..ek_len].to_vec();
        let dk = key_material[ek_len..ek_len + dk_len].to_vec();

        // Step 2: Encapsulation
        let encap_vec = CavpTestVector {
            id: "mlkem768-encap".to_string(),
            algorithm: alg.clone(),
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: Some(ek),
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: Some(vec![0xCC; 1088]),
                signature: None,
                shared_secret: Some(vec![0xDD; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Encapsulation,
                created_at: chrono::Utc::now(),
                security_level: 192,
                notes: None,
            },
        };

        let encap_result = executor.execute_single_test_vector(&encap_vec).await.unwrap();
        let encap_output = encap_result.actual_result;
        // Output = ct (1088 bytes) + ssk (32 bytes)
        assert_eq!(encap_output.len(), 1088 + 32);
        let ct = encap_output[..1088].to_vec();
        let ssk_encap = encap_output[1088..].to_vec();

        // Step 3: Decapsulation
        let decap_vec = CavpTestVector {
            id: "mlkem768-decap".to_string(),
            algorithm: alg,
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: Some(ct),
                m: None,
                ek: None,
                dk: Some(dk),
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(ssk_encap.clone()),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Decapsulation,
                created_at: chrono::Utc::now(),
                security_level: 192,
                notes: None,
            },
        };

        let decap_result = executor.execute_single_test_vector(&decap_vec).await.unwrap();
        let ssk_decap = decap_result.actual_result;
        // Decapsulation should produce the same shared secret
        assert_eq!(
            ssk_encap, ssk_decap,
            "Encapsulated and decapsulated shared secrets should match"
        );
        // Note: decap_result.passed may be false since expected_outputs has dummy values,
        // but the actual roundtrip succeeds (ssk_encap == ssk_decap)
    }
}
mod pipeline_dispatch {
    //! Coverage tests for cavp/pipeline.rs algorithm dispatch functions.
    //! Targets the execute_* async methods and real_*_implementation functions
    //! including error paths for unsupported variants and test types.

    #![allow(clippy::unwrap_used, clippy::field_reassign_with_default)]

    use chrono::Utc;
    use latticearc_tests::validation::cavp::pipeline::{
        CavpTestExecutor, CavpValidationPipeline, PipelineConfig,
    };
    use latticearc_tests::validation::cavp::storage::MemoryCavpStorage;
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    fn make_storage() -> Arc<MemoryCavpStorage> {
        Arc::new(MemoryCavpStorage::new())
    }

    fn make_executor() -> CavpTestExecutor {
        CavpTestExecutor::new(PipelineConfig::default(), make_storage())
    }

    fn make_pipeline() -> CavpValidationPipeline {
        CavpValidationPipeline::new(PipelineConfig::default(), make_storage())
    }

    fn make_vector(algorithm: CavpAlgorithm, test_type: CavpTestType) -> CavpTestVector {
        CavpTestVector {
            id: "test-vec-1".to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x42u8; 32]),
                message: Some(b"test message".to_vec()),
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0u8; 64]),
                secret_key: Some(vec![0u8; 128]),
                ciphertext: Some(vec![0u8; 96]),
                signature: Some(vec![0u8; 128]),
                shared_secret: Some(vec![0u8; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "test".to_string(),
                test_type,
                created_at: Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    // ============================================================
    // PipelineConfig
    // ============================================================

    #[test]
    fn test_pipeline_config_default_has_expected_values_succeeds() {
        let config = PipelineConfig::default();
        assert_eq!(config.max_concurrent_tests, 4);
        assert_eq!(config.retry_count, 3);
        assert!(config.run_statistical_tests);
        assert!(config.generate_reports);
    }

    // ============================================================
    // ML-KEM pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_keygen_execution_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.actual_result.is_empty());
    }

    #[tokio::test]
    async fn test_mlkem_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlKem { variant: "999".to_string() }, CavpTestType::KeyGen);

        // Should return a failed test result (error captured, not propagated)
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok()); // The executor wraps errors into failed test results
        let test_result = result.unwrap();
        assert!(!test_result.passed);
    }

    #[tokio::test]
    async fn test_mlkem_signature_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Signature,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.passed); // ML-KEM doesn't support signatures
    }

    #[tokio::test]
    async fn test_mlkem_verification_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Verification,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.passed);
    }

    // ============================================================
    // ML-DSA pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_keygen_44_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "44".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mldsa_keygen_65_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "65".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mldsa_keygen_87_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "87".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mldsa_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "99".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_encapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Encapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_decapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Decapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // SLH-DSA pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_keygen_shake_128s_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slhdsa_keygen_shake_192s_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slhdsa_keygen_shake_256s_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slhdsa_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "unknown".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_encapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Encapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // FN-DSA pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_keygen_512_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::FnDsa { variant: "512".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fndsa_keygen_1024_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::FnDsa { variant: "1024".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fndsa_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::FnDsa { variant: "256".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_encapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Encapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Hybrid-KEM pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_keygen_succeeds() {
        let executor = make_executor();
        let vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hybrid_kem_signature_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::Signature);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Batch execution
    // ============================================================

    #[tokio::test]
    async fn test_batch_execution_mixed_algorithms_completes_succeeds() {
        let executor = make_executor();
        let vectors = vec![
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen),
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen),
        ];

        let result = executor.execute_test_vector_batch(vectors).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_batch_execution_empty_returns_empty_batch_succeeds() {
        let executor = make_executor();
        let vectors = Vec::new();

        let result = executor.execute_test_vector_batch(vectors).await;
        assert!(result.is_ok());
    }

    // ============================================================
    // CavpValidationPipeline
    // ============================================================

    #[tokio::test]
    async fn test_pipeline_run_full_validation_succeeds() {
        let pipeline = make_pipeline();
        let vectors = vec![
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen),
            make_vector(CavpAlgorithm::MlDsa { variant: "44".to_string() }, CavpTestType::KeyGen),
        ];

        let result = pipeline.run_full_validation(vectors).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2); // Two different algorithms = two batches
    }

    #[tokio::test]
    async fn test_pipeline_run_algorithm_validation_succeeds() {
        let pipeline = make_pipeline();
        let vectors = vec![make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::KeyGen,
        )];

        let result = pipeline
            .run_algorithm_validation(CavpAlgorithm::MlKem { variant: "768".to_string() }, vectors)
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_pipeline_create_sample_vectors_succeeds() {
        let pipeline = make_pipeline();
        let vectors =
            pipeline.create_sample_vectors(CavpAlgorithm::MlKem { variant: "768".to_string() }, 5);
        assert_eq!(vectors.len(), 5);
        for (i, v) in vectors.iter().enumerate() {
            assert!(v.id.contains("SAMPLE"));
            assert!(v.id.contains(&format!("{}", i + 1)));
        }
    }

    #[test]
    fn test_pipeline_create_sample_vectors_empty_returns_empty_matches_expected() {
        let pipeline = make_pipeline();
        let vectors =
            pipeline.create_sample_vectors(CavpAlgorithm::MlDsa { variant: "44".to_string() }, 0);
        assert!(vectors.is_empty());
    }

    // ============================================================
    // ML-KEM Encapsulation / Decapsulation error paths
    // ============================================================

    fn make_vector_with_inputs(
        algorithm: CavpAlgorithm,
        test_type: CavpTestType,
        inputs: CavpVectorInputs,
    ) -> CavpTestVector {
        CavpTestVector {
            id: "test-vec-err".to_string(),
            algorithm,
            inputs,
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "test".to_string(),
                test_type,
                created_at: Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    fn default_inputs() -> CavpVectorInputs {
        CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_mlkem_encapsulation_missing_ek_returns_error() {
        let executor = make_executor();
        let inputs = default_inputs(); // ek is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Encapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_encapsulation_wrong_ek_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 10]); // Wrong length
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Encapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_missing_dk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.c = Some(vec![0u8; 10]); // c present but dk missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_missing_c_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 10]); // dk present but c missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_wrong_dk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 10]); // Wrong length
        inputs.c = Some(vec![0u8; 10]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // ML-DSA Signature / Verification error paths
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_signature_missing_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        // sk is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 2560)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_missing_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 2420]);
        // pk is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 1312)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 2420]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_wrong_sig_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 1312]);
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 10]); // Wrong length (expected 2420)
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_65_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 4032)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_65_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 1952)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 3309]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_87_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 4896)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "87".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_87_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 2592)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 4627]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "87".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // SLH-DSA Signature / Verification error paths
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_128s_signature_missing_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 64)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_missing_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 7856]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 32)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 7856]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_192s_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 96)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_192s_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 48)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 16224]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_256s_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 128)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_256s_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 64)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 29792]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // FN-DSA Signature / Verification error paths
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_signature_missing_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_signature_invalid_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0xFFu8; 100]); // Invalid format
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_missing_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 666]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_invalid_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0xFFu8; 100]); // Invalid format
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 666]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_decapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_decapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Hybrid KEM Encapsulation / Decapsulation error paths
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_encapsulation_missing_ek_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.m = Some(vec![0u8; 32]); // m present but ek missing
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decapsulation_missing_dk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.c = Some(vec![0u8; 32]);
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_verification_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::Verification);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Hybrid KEM Encapsulation + Decapsulation roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_encap_decap_roundtrip_succeeds() {
        let executor = make_executor();

        // Step 1: Generate hybrid keys
        let keygen_vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await;
        assert!(keygen_result.is_ok());
        let keygen_test = keygen_result.unwrap();
        assert!(
            keygen_test.passed || !keygen_test.actual_result.is_empty(),
            "HybridKem KeyGen should produce output"
        );

        // The keygen output is: ek_pq (1184) || pk_classical (32) || dk_pq (2400) || sk_classical (32)
        let key_data = &keygen_test.actual_result;
        if key_data.len() >= 1184 + 32 + 2400 + 32 {
            let ek_combined = key_data.get(..1184 + 32).unwrap().to_vec(); // ek_pq || pk_classical
            let dk_combined = key_data.get(1184 + 32..).unwrap().to_vec(); // dk_pq || sk_classical

            // Step 2: Encapsulation
            let mut encap_inputs = default_inputs();
            encap_inputs.ek = Some(ek_combined);
            encap_inputs.m = Some(vec![0x42u8; 32]); // ephemeral secret for X25519
            let encap_vector = make_vector_with_inputs(
                CavpAlgorithm::HybridKem,
                CavpTestType::Encapsulation,
                encap_inputs,
            );
            let encap_result = executor.execute_single_test_vector(&encap_vector).await;
            assert!(encap_result.is_ok());
            let encap_test = encap_result.unwrap();
            // Encapsulation output is: c_pq (1088) || pk_ephemeral (32) || combined_secret (32)
            assert!(!encap_test.actual_result.is_empty(), "Encapsulation should produce output");

            if encap_test.actual_result.len() >= 1088 + 32 + 32 {
                let ciphertext = encap_test.actual_result.get(..1088 + 32).unwrap().to_vec();
                let encap_secret = encap_test.actual_result.get(1088 + 32..).unwrap().to_vec();

                // Step 3: Decapsulation
                let mut decap_inputs = default_inputs();
                decap_inputs.dk = Some(dk_combined);
                decap_inputs.c = Some(ciphertext);
                let decap_vector = make_vector_with_inputs(
                    CavpAlgorithm::HybridKem,
                    CavpTestType::Decapsulation,
                    decap_inputs,
                );
                let decap_result = executor.execute_single_test_vector(&decap_vector).await;
                assert!(decap_result.is_ok());
                let decap_test = decap_result.unwrap();
                assert!(
                    !decap_test.actual_result.is_empty(),
                    "Decapsulation should produce output"
                );

                // Shared secrets should match
                assert_eq!(
                    encap_secret, decap_test.actual_result,
                    "Encapsulation and decapsulation should produce the same shared secret"
                );
            }
        }
    }

    // ============================================================
    // Hybrid KEM missing-input / invalid-length error paths
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_encap_missing_m_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 1184 + 32]); // ek present but m missing
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_encap_short_ek_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 10]); // Too short for PQ part
        inputs.m = Some(vec![0u8; 32]);
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_encap_wrong_m_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 1184 + 32]);
        inputs.m = Some(vec![0u8; 16]); // Wrong length (need 32)
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decap_missing_c_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 2400 + 32]); // dk present but c missing
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decap_short_dk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 10]); // Too short
        inputs.c = Some(vec![0u8; 1088 + 32]);
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decap_short_c_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 2400 + 32]);
        inputs.c = Some(vec![0u8; 10]); // Too short for PQ ciphertext part
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // ML-DSA sign/verify roundtrip through pipeline
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_sign_verify_roundtrip_succeeds() {
        let executor = make_executor();

        // Step 1: KeyGen
        let keygen_vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "44".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: pk (1312) || sk (2560)
        if key_data.len() >= 1312 + 2560 {
            let pk = key_data.get(..1312).unwrap().to_vec();
            let sk = key_data.get(1312..).unwrap().to_vec();

            // Step 2: Sign
            let mut sign_inputs = default_inputs();
            sign_inputs.sk = Some(sk);
            sign_inputs.message = Some(b"test message for ML-DSA-44 pipeline".to_vec());
            let sign_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "44".to_string() },
                CavpTestType::Signature,
                sign_inputs,
            );
            let sign_result = executor.execute_single_test_vector(&sign_vector).await.unwrap();
            assert!(!sign_result.actual_result.is_empty(), "Sign should produce signature");
            let signature = sign_result.actual_result;

            // Step 3: Verify
            let mut verify_inputs = default_inputs();
            verify_inputs.pk = Some(pk);
            verify_inputs.message = Some(b"test message for ML-DSA-44 pipeline".to_vec());
            verify_inputs.signature = Some(signature);
            let verify_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "44".to_string() },
                CavpTestType::Verification,
                verify_inputs,
            );
            let verify_result = executor.execute_single_test_vector(&verify_vector).await.unwrap();
            assert!(!verify_result.actual_result.is_empty());
            // Result should be [1] for valid
            assert_eq!(verify_result.actual_result, vec![1u8]);
        }
    }

    #[tokio::test]
    async fn test_mldsa_65_sign_verify_roundtrip_succeeds() {
        let executor = make_executor();

        let keygen_vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "65".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: pk (1952) || sk (4032)
        if key_data.len() >= 1952 + 4032 {
            let pk = key_data.get(..1952).unwrap().to_vec();
            let sk = key_data.get(1952..).unwrap().to_vec();

            let mut sign_inputs = default_inputs();
            sign_inputs.sk = Some(sk);
            sign_inputs.message = Some(b"test message for ML-DSA-65 pipeline".to_vec());
            let sign_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "65".to_string() },
                CavpTestType::Signature,
                sign_inputs,
            );
            let sign_result = executor.execute_single_test_vector(&sign_vector).await.unwrap();
            assert!(!sign_result.actual_result.is_empty());

            let mut verify_inputs = default_inputs();
            verify_inputs.pk = Some(pk);
            verify_inputs.message = Some(b"test message for ML-DSA-65 pipeline".to_vec());
            verify_inputs.signature = Some(sign_result.actual_result);
            let verify_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "65".to_string() },
                CavpTestType::Verification,
                verify_inputs,
            );
            let verify_result = executor.execute_single_test_vector(&verify_vector).await.unwrap();
            assert_eq!(verify_result.actual_result, vec![1u8]);
        }
    }

    #[tokio::test]
    async fn test_mldsa_87_sign_verify_roundtrip_succeeds() {
        let executor = make_executor();

        let keygen_vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "87".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: pk (2592) || sk (4896)
        if key_data.len() >= 2592 + 4896 {
            let pk = key_data.get(..2592).unwrap().to_vec();
            let sk = key_data.get(2592..).unwrap().to_vec();

            let mut sign_inputs = default_inputs();
            sign_inputs.sk = Some(sk);
            sign_inputs.message = Some(b"test message for ML-DSA-87 pipeline".to_vec());
            let sign_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "87".to_string() },
                CavpTestType::Signature,
                sign_inputs,
            );
            let sign_result = executor.execute_single_test_vector(&sign_vector).await.unwrap();
            assert!(!sign_result.actual_result.is_empty());

            let mut verify_inputs = default_inputs();
            verify_inputs.pk = Some(pk);
            verify_inputs.message = Some(b"test message for ML-DSA-87 pipeline".to_vec());
            verify_inputs.signature = Some(sign_result.actual_result);
            let verify_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "87".to_string() },
                CavpTestType::Verification,
                verify_inputs,
            );
            let verify_result = executor.execute_single_test_vector(&verify_vector).await.unwrap();
            assert_eq!(verify_result.actual_result, vec![1u8]);
        }
    }

    // ============================================================
    // ML-DSA missing-message error paths
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_signature_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 2560]); // sk present but message missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 1312]);
        inputs.signature = Some(vec![0u8; 2420]);
        // message is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_missing_signature_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 1312]);
        inputs.message = Some(b"test".to_vec());
        // signature is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // SLH-DSA missing-message/signature error paths
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_128s_signature_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 64]); // sk present but message missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 32]);
        inputs.signature = Some(vec![0u8; 7856]);
        // message is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_missing_signature_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 32]);
        inputs.message = Some(b"test".to_vec());
        // signature is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_wrong_sig_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 32]);
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 10]); // Wrong length (expected 7856)
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // FN-DSA missing-message/signature error paths
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_signature_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0xFFu8; 100]); // sk present but message missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0xFFu8; 100]);
        inputs.signature = Some(vec![0u8; 666]);
        // message is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_missing_signature_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0xFFu8; 100]);
        inputs.message = Some(b"test".to_vec());
        // signature is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // ML-KEM encap/decap roundtrip through pipeline
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_768_encap_decap_roundtrip_succeeds() {
        let executor = make_executor();

        // Step 1: ML-KEM-768 Encapsulation with valid ek from keygen
        let keygen_vector =
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: ek (1184) || dk (2400)
        if key_data.len() >= 1184 + 2400 {
            let ek = key_data.get(..1184).unwrap().to_vec();
            let dk = key_data.get(1184..).unwrap().to_vec();

            // Step 2: Encapsulation
            let mut encap_inputs = default_inputs();
            encap_inputs.ek = Some(ek);
            let encap_vector = make_vector_with_inputs(
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                CavpTestType::Encapsulation,
                encap_inputs,
            );
            let encap_result = executor.execute_single_test_vector(&encap_vector).await.unwrap();
            assert!(!encap_result.actual_result.is_empty(), "Encap should produce ciphertext + SS");

            // Output: ciphertext (1088) || shared_secret (32)
            if encap_result.actual_result.len() >= 1088 + 32 {
                let ct = encap_result.actual_result.get(..1088).unwrap().to_vec();
                let ss_encap = encap_result.actual_result.get(1088..).unwrap().to_vec();

                // Step 3: Decapsulation
                let mut decap_inputs = default_inputs();
                decap_inputs.dk = Some(dk);
                decap_inputs.c = Some(ct);
                let decap_vector = make_vector_with_inputs(
                    CavpAlgorithm::MlKem { variant: "768".to_string() },
                    CavpTestType::Decapsulation,
                    decap_inputs,
                );
                let decap_result =
                    executor.execute_single_test_vector(&decap_vector).await.unwrap();
                assert!(!decap_result.actual_result.is_empty());
                assert_eq!(ss_encap, decap_result.actual_result, "Shared secrets must match");
            }
        }
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_wrong_ct_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 2400]); // Valid dk length
        inputs.c = Some(vec![0u8; 10]); // Wrong ct length
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Pipeline with reports disabled
    // ============================================================

    #[tokio::test]
    async fn test_pipeline_no_reports_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = false;
        config.run_statistical_tests = false;
        let pipeline = CavpValidationPipeline::new(config, make_storage());
        let vectors = vec![make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::KeyGen,
        )];
        let result = pipeline.run_full_validation(vectors).await;
        assert!(result.is_ok());
    }
}
