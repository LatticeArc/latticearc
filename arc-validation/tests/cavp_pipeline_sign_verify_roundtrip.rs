//! Coverage tests for CAVP pipeline Signature and Verification paths.
//! Exercises real crypto roundtrips: KeyGen → Sign → Verify for each algorithm variant.
//! Targets pipeline.rs lines: ML-DSA sign/verify (44, 65, 87), SLH-DSA sign/verify
//! (shake-128s, 192s, 256s), FN-DSA sign/verify (512, 1024).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::redundant_closure_for_method_calls,
    clippy::useless_format
)]

use arc_validation::cavp::pipeline::{CavpTestExecutor, PipelineConfig};
use arc_validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
use arc_validation::cavp::types::*;
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
    assert_eq!(ssk_encap, ssk_decap, "Encapsulated and decapsulated shared secrets should match");
    // Note: decap_result.passed may be false since expected_outputs has dummy values,
    // but the actual roundtrip succeeds (ssk_encap == ssk_decap)
}
