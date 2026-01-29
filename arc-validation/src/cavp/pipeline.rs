#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: CAVP test execution pipeline.
// - Processes NIST test vectors with known-size binary data
// - Statistics and metrics for batch execution
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unused_async)] // Test execution functions are async for future extensibility

use crate::cavp::compliance::CavpComplianceGenerator;
use crate::cavp::storage::CavpStorage;
use crate::cavp::types::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info};

// Import PQ cryptographic primitives
use crate::cavp::{
    CavpAlgorithm, CavpBatchResult, CavpComplianceReport, CavpTestMetadata, CavpTestResult,
    CavpTestType, CavpTestVector, ComplianceCriteria, ComplianceStatus, ComplianceTestResult,
    MemoryUsageMetrics, PerformanceMetrics, SecurityRequirement, TestCategory, TestConfiguration,
    TestEnvironment, TestResult, TestSummary, ThroughputMetrics,
};
use fips203::ml_kem_768;
use fips203::traits::{KeyGen, SerDes};

// Import SLH-DSA SHAKE variants from fips205
use fips205::{slh_dsa_shake_128s, slh_dsa_shake_192s, slh_dsa_shake_256s};

#[allow(unused_imports)]
use fips203::traits::{Decaps, Encaps, SerDes as Fips203SerDes};
use fips204::traits::{
    SerDes as Fips204SerDes, Signer as Fips204Signer, Verifier as Fips204Verifier,
};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use fips205::traits::{
    SerDes as Fips205SerDes, Signer as Fips205Signer, Verifier as Fips205Verifier,
};

// Import FN-DSA types and traits
use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator,
    KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard,
    sign_key_size, vrfy_key_size,
};

/// CAVP validation pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Maximum concurrent tests
    pub max_concurrent_tests: usize,
    /// Timeout per test
    pub test_timeout: Duration,
    /// Retry count for failed tests
    pub retry_count: usize,
    /// Whether to run statistical tests
    pub run_statistical_tests: bool,
    /// Whether to generate compliance reports
    pub generate_reports: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tests: 4,
            test_timeout: Duration::from_secs(30),
            retry_count: 3,
            run_statistical_tests: true,
            generate_reports: true,
        }
    }
}

/// CAVP test executor
pub struct CavpTestExecutor {
    config: PipelineConfig,
    storage: Arc<dyn CavpStorage>,
}

impl CavpTestExecutor {
    /// Creates a new CAVP test executor with the given configuration and storage.
    pub fn new(config: PipelineConfig, storage: Arc<dyn CavpStorage>) -> Self {
        Self { config, storage }
    }

    /// Executes a batch of CAVP test vectors and returns the aggregated results.
    ///
    /// # Errors
    /// Returns an error if test execution or storage operations fail.
    pub async fn execute_test_vector_batch(
        &self,
        vectors: Vec<CavpTestVector>,
    ) -> Result<CavpBatchResult> {
        let batch_id = format!("CAVP-BATCH-{}", Utc::now().timestamp());
        let algorithm = vectors
            .first()
            .map(|v| v.algorithm.clone())
            .unwrap_or(CavpAlgorithm::MlKem { variant: "768".to_string() });

        let mut batch_result = CavpBatchResult::new(batch_id.clone(), algorithm);
        let start_time = Instant::now();

        info!("Starting CAVP batch execution: {} with {} test vectors", batch_id, vectors.len());

        for vector in vectors {
            let test_result = self.execute_single_test_vector(&vector).await?;
            batch_result.add_test_result(test_result);
        }

        batch_result.total_execution_time = start_time.elapsed();
        batch_result.update_status();

        if let Err(e) = self.storage.store_batch(&batch_result) {
            error!("Failed to store batch result: {}", e);
        }

        info!(
            "Completed CAVP batch execution: {} with pass rate: {:.2}%",
            batch_id, batch_result.pass_rate
        );

        Ok(batch_result)
    }

    /// Executes a single CAVP test vector and returns the result.
    ///
    /// # Errors
    /// Returns an error if storage operations fail; test failures are captured in the result.
    pub async fn execute_single_test_vector(
        &self,
        vector: &CavpTestVector,
    ) -> Result<CavpTestResult> {
        let test_id =
            format!("CAVP-TEST-{}-{}", vector.algorithm.name(), Utc::now().timestamp_micros());
        let start_time = Instant::now();

        let metadata = CavpTestMetadata {
            environment: TestEnvironment {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                rust_version: "1.70.0".to_string(),
                compiler: "rustc".to_string(),
                framework_version: "1.0.0".to_string(),
            },
            security_level: vector.metadata.security_level,
            vector_version: vector.metadata.version.clone(),
            implementation_version: "1.0.0".to_string(),
            configuration: TestConfiguration {
                iterations: 1,
                timeout: self.config.test_timeout,
                statistical_tests: self.config.run_statistical_tests,
                parameters: vector.inputs.parameters.clone(),
            },
        };

        let result = match &vector.algorithm {
            CavpAlgorithm::MlKem { variant } => {
                self.execute_mlkem_test(&test_id, variant, vector, &metadata, start_time).await
            }
            CavpAlgorithm::MlDsa { variant } => {
                self.execute_mldsa_test(&test_id, variant, vector, &metadata, start_time).await
            }
            CavpAlgorithm::SlhDsa { variant } => {
                self.execute_slhdsa_test(&test_id, variant, vector, &metadata, start_time).await
            }
            CavpAlgorithm::FnDsa { variant } => {
                self.execute_fndsa_test(&test_id, variant, vector, &metadata, start_time).await
            }
            CavpAlgorithm::HybridKem => {
                self.execute_hybrid_kem_test(&test_id, vector, &metadata, start_time).await
            }
        };

        let test_result = result.unwrap_or_else(|e| {
            CavpTestResult::failed(
                test_id,
                vector.algorithm.clone(),
                vector.id.clone(),
                Vec::new(),
                vector.expected_outputs.public_key.clone().unwrap_or_default(),
                start_time.elapsed(),
                e.to_string(),
                metadata,
            )
        });

        if let Err(e) = self.storage.store_result(&test_result) {
            error!("Failed to store test result: {}", e);
        }

        Ok(test_result)
    }

    async fn execute_mlkem_test(
        &self,
        test_id: &str,
        variant: &str,
        vector: &CavpTestVector,
        metadata: &CavpTestMetadata,
        start_time: Instant,
    ) -> Result<CavpTestResult> {
        info!("Executing ML-KEM-{} test: {}", variant, vector.id);

        let actual_result = Self::real_mlkem_implementation(vector, variant)?;
        let expected_result = vector.expected_outputs.public_key.clone().unwrap_or_default();

        Ok(CavpTestResult::new(
            test_id.to_string(),
            vector.algorithm.clone(),
            vector.id.clone(),
            actual_result,
            expected_result,
            start_time.elapsed(),
            metadata.clone(),
        ))
    }

    async fn execute_mldsa_test(
        &self,
        test_id: &str,
        variant: &str,
        vector: &CavpTestVector,
        metadata: &CavpTestMetadata,
        start_time: Instant,
    ) -> Result<CavpTestResult> {
        info!("Executing ML-DSA-{} test: {}", variant, vector.id);

        let actual_result = Self::real_mldsa_implementation(vector, variant)?;
        let expected_result = vector.expected_outputs.signature.clone().unwrap_or_default();

        Ok(CavpTestResult::new(
            test_id.to_string(),
            vector.algorithm.clone(),
            vector.id.clone(),
            actual_result,
            expected_result,
            start_time.elapsed(),
            metadata.clone(),
        ))
    }

    async fn execute_slhdsa_test(
        &self,
        test_id: &str,
        variant: &str,
        vector: &CavpTestVector,
        metadata: &CavpTestMetadata,
        start_time: Instant,
    ) -> Result<CavpTestResult> {
        info!("Executing SLH-DSA-{} test: {}", variant, vector.id);

        let actual_result = self.real_slhdsa_implementation(vector, variant)?;
        let expected_result = vector.expected_outputs.signature.clone().unwrap_or_default();

        Ok(CavpTestResult::new(
            test_id.to_string(),
            vector.algorithm.clone(),
            vector.id.clone(),
            actual_result,
            expected_result,
            start_time.elapsed(),
            metadata.clone(),
        ))
    }

    async fn execute_fndsa_test(
        &self,
        test_id: &str,
        variant: &str,
        vector: &CavpTestVector,
        metadata: &CavpTestMetadata,
        start_time: Instant,
    ) -> Result<CavpTestResult> {
        info!("Executing FN-DSA-{} test: {}", variant, vector.id);

        let actual_result = Self::real_fndsa_implementation(vector, variant)?;
        let expected_result = vector.expected_outputs.signature.clone().unwrap_or_default();

        Ok(CavpTestResult::new(
            test_id.to_string(),
            vector.algorithm.clone(),
            vector.id.clone(),
            actual_result,
            expected_result,
            start_time.elapsed(),
            metadata.clone(),
        ))
    }

    async fn execute_hybrid_kem_test(
        &self,
        test_id: &str,
        vector: &CavpTestVector,
        metadata: &CavpTestMetadata,
        start_time: Instant,
    ) -> Result<CavpTestResult> {
        info!("Executing Hybrid-KEM test: {}", vector.id);

        let actual_result = Self::real_hybrid_kem_implementation(vector)?;
        let expected_result = vector.expected_outputs.shared_secret.clone().unwrap_or_default();

        Ok(CavpTestResult::new(
            test_id.to_string(),
            vector.algorithm.clone(),
            vector.id.clone(),
            actual_result,
            expected_result,
            start_time.elapsed(),
            metadata.clone(),
        ))
    }

    fn real_mlkem_implementation(vector: &CavpTestVector, variant: &str) -> Result<Vec<u8>> {
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                // Generate key pair using fips203 API
                let (ek, dk) = match variant {
                    "768" => {
                        // Use KeyGen trait implementation
                        use fips203::traits::KeyGen;
                        <ml_kem_768::KG as KeyGen>::try_keygen()
                            .map_err(|e| anyhow::anyhow!("ML-KEM keygen failed: {}", e))?
                    }
                    _ => return Err(anyhow::anyhow!("Unsupported ML-KEM variant: {}", variant)),
                };
                // Return concatenation of ek and dk for CAVP format
                let ek_bytes = Fips203SerDes::into_bytes(ek);
                let dk_bytes = Fips203SerDes::into_bytes(dk);
                let mut result = ek_bytes.to_vec();
                result.extend_from_slice(&dk_bytes);
                Ok(result)
            }
            CavpTestType::Encapsulation => {
                // Encapsulate using provided ek
                let ek_bytes = vector
                    .inputs
                    .ek
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing ek for encapsulation"))?;
                let ek_arr: [u8; ml_kem_768::EK_LEN] =
                    ek_bytes.as_slice().try_into().map_err(|e| {
                        anyhow::anyhow!(
                            "Invalid ek length: expected {}, got {} ({})",
                            ml_kem_768::EK_LEN,
                            ek_bytes.len(),
                            e
                        )
                    })?;
                let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid encaps key: {}", e))?;
                let (ssk, ct) = <ml_kem_768::EncapsKey as Encaps>::try_encaps(&ek)
                    .map_err(|e| anyhow::anyhow!("Encapsulation failed: {}", e))?;
                // Return concatenation of ct and ssk for CAVP format
                let ct_bytes = Fips203SerDes::into_bytes(ct);
                let ssk_bytes = Fips203SerDes::into_bytes(ssk);
                let mut result = ct_bytes.to_vec();
                result.extend_from_slice(&ssk_bytes);
                Ok(result)
            }
            CavpTestType::Decapsulation => {
                // Decapsulate using provided dk and c
                let dk_bytes = vector
                    .inputs
                    .dk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing dk for decapsulation"))?;
                let c_bytes = vector
                    .inputs
                    .c
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing c for decapsulation"))?;
                let dk_arr: [u8; ml_kem_768::DK_LEN] =
                    dk_bytes.as_slice().try_into().map_err(|e| {
                        anyhow::anyhow!(
                            "Invalid dk length: expected {}, got {} ({})",
                            ml_kem_768::DK_LEN,
                            dk_bytes.len(),
                            e
                        )
                    })?;
                let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid decaps key: {}", e))?;
                let ct_arr: [u8; ml_kem_768::CT_LEN] =
                    c_bytes.as_slice().try_into().map_err(|e| {
                        anyhow::anyhow!(
                            "Invalid ct length: expected {}, got {} ({})",
                            ml_kem_768::CT_LEN,
                            c_bytes.len(),
                            e
                        )
                    })?;
                let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ciphertext: {}", e))?;
                let ssk = <ml_kem_768::DecapsKey as Decaps>::try_decaps(&dk, &ct)
                    .map_err(|e| anyhow::anyhow!("Decapsulation failed: {}", e))?;
                let ssk_bytes: [u8; 32] = SerDes::into_bytes(ssk);
                Ok(ssk_bytes.to_vec())
            }
            CavpTestType::Signature | CavpTestType::Verification => {
                Err(anyhow::anyhow!("ML-KEM does not support signature/verification operations"))
            }
        }
    }

    #[allow(clippy::unused_self)] // Method kept on instance for API consistency
    fn real_slhdsa_implementation(
        &self,
        vector: &CavpTestVector,
        variant: &str,
    ) -> Result<Vec<u8>> {
        // Handle each variant separately to avoid type mismatches
        match variant {
            "shake-128s" => Self::slhdsa_shake_128s_impl(vector),
            "shake-192s" => Self::slhdsa_shake_192s_impl(vector),
            "shake-256s" => Self::slhdsa_shake_256s_impl(vector),
            _ => Err(anyhow::anyhow!("Unsupported SLH-DSA variant: {}", variant)),
        }
    }

    fn slhdsa_shake_128s_impl(vector: &CavpTestVector) -> Result<Vec<u8>> {
        use fips205::traits::SerDes as Fips205SerDesLocal;
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                let (pk, sk) = slh_dsa_shake_128s::try_keygen()
                    .map_err(|e| anyhow::anyhow!("Keygen failed: {}", e))?;
                let pk_bytes = pk.into_bytes();
                let sk_bytes = sk.into_bytes();
                let mut result = pk_bytes.to_vec();
                result.extend_from_slice(&sk_bytes);
                Ok(result)
            }
            CavpTestType::Signature => {
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;
                let sk_arr: [u8; 64] = sk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid sk length for shake-128s: expected 64, got {} ({})",
                        sk_bytes.len(),
                        e
                    )
                })?;
                let sk = slh_dsa_shake_128s::PrivateKey::try_from_bytes(&sk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
                let signature = sk
                    .try_sign(message, b"", true)
                    .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;
                Ok(signature.to_vec())
            }
            CavpTestType::Verification => {
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;
                let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid pk length for shake-128s: expected 32, got {} ({})",
                        pk_bytes.len(),
                        e
                    )
                })?;
                let pk = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
                let sig_arr: [u8; 7856] = sig_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid signature length for shake-128s: expected 7856, got {} ({})",
                        sig_bytes.len(),
                        e
                    )
                })?;
                let is_valid = pk.verify(message, &sig_arr, b"");
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "SLH-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn slhdsa_shake_192s_impl(vector: &CavpTestVector) -> Result<Vec<u8>> {
        use fips205::traits::SerDes as Fips205SerDesLocal;
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                let (pk, sk) = slh_dsa_shake_192s::try_keygen()
                    .map_err(|e| anyhow::anyhow!("Keygen failed: {}", e))?;
                let pk_bytes = pk.into_bytes();
                let sk_bytes = sk.into_bytes();
                let mut result = pk_bytes.to_vec();
                result.extend_from_slice(&sk_bytes);
                Ok(result)
            }
            CavpTestType::Signature => {
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;
                let sk_arr: [u8; 96] = sk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid sk length for shake-192s: expected 96, got {} ({})",
                        sk_bytes.len(),
                        e
                    )
                })?;
                let sk = slh_dsa_shake_192s::PrivateKey::try_from_bytes(&sk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
                let signature = sk
                    .try_sign(message, b"", true)
                    .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;
                Ok(signature.to_vec())
            }
            CavpTestType::Verification => {
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;
                let pk_arr: [u8; 48] = pk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid pk length for shake-192s: expected 48, got {} ({})",
                        pk_bytes.len(),
                        e
                    )
                })?;
                let pk = slh_dsa_shake_192s::PublicKey::try_from_bytes(&pk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
                let sig_arr: [u8; 16224] = sig_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid signature length for shake-192s: expected 16224, got {} ({})",
                        sig_bytes.len(),
                        e
                    )
                })?;
                let is_valid = pk.verify(message, &sig_arr, b"");
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "SLH-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn slhdsa_shake_256s_impl(vector: &CavpTestVector) -> Result<Vec<u8>> {
        use fips205::traits::SerDes as Fips205SerDesLocal;
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                let (pk, sk) = slh_dsa_shake_256s::try_keygen()
                    .map_err(|e| anyhow::anyhow!("Keygen failed: {}", e))?;
                let pk_bytes = pk.into_bytes();
                let sk_bytes = sk.into_bytes();
                let mut result = pk_bytes.to_vec();
                result.extend_from_slice(&sk_bytes);
                Ok(result)
            }
            CavpTestType::Signature => {
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;
                let sk_arr: [u8; 128] = sk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid sk length for shake-256s: expected 128, got {} ({})",
                        sk_bytes.len(),
                        e
                    )
                })?;
                let sk = slh_dsa_shake_256s::PrivateKey::try_from_bytes(&sk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
                let signature = sk
                    .try_sign(message, b"", true)
                    .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;
                Ok(signature.to_vec())
            }
            CavpTestType::Verification => {
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;
                let pk_arr: [u8; 64] = pk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid pk length for shake-256s: expected 64, got {} ({})",
                        pk_bytes.len(),
                        e
                    )
                })?;
                let pk = slh_dsa_shake_256s::PublicKey::try_from_bytes(&pk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
                let sig_arr: [u8; 29792] = sig_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid signature length for shake-256s: expected 29792, got {} ({})",
                        sig_bytes.len(),
                        e
                    )
                })?;
                let is_valid = pk.verify(message, &sig_arr, b"");
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "SLH-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn real_fndsa_implementation(vector: &CavpTestVector, variant: &str) -> Result<Vec<u8>> {
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                // Generate key pair using fn-dsa API
                let logn = match variant {
                    "512" => FN_DSA_LOGN_512,
                    "1024" => FN_DSA_LOGN_1024,
                    _ => return Err(anyhow::anyhow!("Unsupported FN-DSA variant: {}", variant)),
                };

                // Create buffers for keys
                let mut sign_key = vec![0u8; sign_key_size(logn)];
                let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

                // Create key pair generator and generate keys
                let mut kg = KeyPairGeneratorStandard::default();
                kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

                // Return concatenation of pk (vk) and sk for CAVP format
                let mut result = vrfy_key;
                result.extend_from_slice(&sign_key);
                Ok(result)
            }
            CavpTestType::Signature => {
                // Sign message using provided sk with proper fn-dsa API
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;

                let logn = match variant {
                    "512" => FN_DSA_LOGN_512,
                    "1024" => FN_DSA_LOGN_1024,
                    _ => return Err(anyhow::anyhow!("Unsupported FN-DSA variant: {}", variant)),
                };

                // Decode the signing key
                let mut sk: SigningKeyStandard = SigningKey::decode(sk_bytes)
                    .ok_or_else(|| anyhow::anyhow!("Failed to decode FN-DSA signing key"))?;

                // Create signature buffer
                let mut signature = vec![0u8; fn_dsa::signature_size(logn)];

                // Sign the message (writes to signature buffer, doesn't return Result)
                sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut signature);

                Ok(signature)
            }
            CavpTestType::Verification => {
                // Verify signature using provided pk with proper fn-dsa API
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;

                // Decode the verifying key
                let vk: VerifyingKeyStandard = match VerifyingKey::decode(pk_bytes) {
                    Some(key) => key,
                    None => return Ok(vec![0]), // Invalid key format
                };

                // Verify the signature
                let is_valid = vk.verify(sig_bytes, &DOMAIN_NONE, &HASH_ID_RAW, message);
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "FN-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn real_mldsa_implementation(vector: &CavpTestVector, variant: &str) -> Result<Vec<u8>> {
        // Handle each variant separately to avoid type mismatches
        match variant {
            "44" => Self::mldsa_44_impl(vector),
            "65" => Self::mldsa_65_impl(vector),
            "87" => Self::mldsa_87_impl(vector),
            _ => Err(anyhow::anyhow!("Unsupported ML-DSA variant: {}", variant)),
        }
    }

    fn mldsa_44_impl(vector: &CavpTestVector) -> Result<Vec<u8>> {
        use fips204::traits::SerDes as Fips204SerDesLocal;
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                let (pk, sk) = ml_dsa_44::try_keygen()
                    .map_err(|e| anyhow::anyhow!("ML-DSA-44 keygen failed: {}", e))?;
                let pk_bytes = pk.into_bytes();
                let sk_bytes = sk.into_bytes();
                let mut result = pk_bytes.to_vec();
                result.extend_from_slice(&sk_bytes);
                Ok(result)
            }
            CavpTestType::Signature => {
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;
                let sk_arr: [u8; 2560] = sk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid sk length for ML-DSA-44: expected 2560, got {} ({})",
                        sk_bytes.len(),
                        e
                    )
                })?;
                let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-44 private key: {}", e))?;
                let signature = sk
                    .try_sign(message, &[])
                    .map_err(|e| anyhow::anyhow!("ML-DSA-44 signing failed: {}", e))?;
                Ok(signature.to_vec())
            }
            CavpTestType::Verification => {
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;
                let pk_arr: [u8; 1312] = pk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid pk length for ML-DSA-44: expected 1312, got {} ({})",
                        pk_bytes.len(),
                        e
                    )
                })?;
                let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-44 public key: {}", e))?;
                let sig_arr: [u8; 2420] = sig_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid signature length for ML-DSA-44: expected 2420, got {} ({})",
                        sig_bytes.len(),
                        e
                    )
                })?;
                let is_valid = pk.verify(message, &sig_arr, &[]);
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "ML-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn mldsa_65_impl(vector: &CavpTestVector) -> Result<Vec<u8>> {
        use fips204::traits::SerDes as Fips204SerDesLocal;
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                let (pk, sk) = ml_dsa_65::try_keygen()
                    .map_err(|e| anyhow::anyhow!("ML-DSA-65 keygen failed: {}", e))?;
                let pk_bytes = pk.into_bytes();
                let sk_bytes = sk.into_bytes();
                let mut result = pk_bytes.to_vec();
                result.extend_from_slice(&sk_bytes);
                Ok(result)
            }
            CavpTestType::Signature => {
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;
                let sk_arr: [u8; 4032] = sk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid sk length for ML-DSA-65: expected 4032, got {} ({})",
                        sk_bytes.len(),
                        e
                    )
                })?;
                let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-65 private key: {}", e))?;
                let signature = sk
                    .try_sign(message, &[])
                    .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {}", e))?;
                Ok(signature.to_vec())
            }
            CavpTestType::Verification => {
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;
                let pk_arr: [u8; 1952] = pk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid pk length for ML-DSA-65: expected 1952, got {} ({})",
                        pk_bytes.len(),
                        e
                    )
                })?;
                let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-65 public key: {}", e))?;
                let sig_arr: [u8; 3309] = sig_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid signature length for ML-DSA-65: expected 3309, got {} ({})",
                        sig_bytes.len(),
                        e
                    )
                })?;
                let is_valid = pk.verify(message, &sig_arr, &[]);
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "ML-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn mldsa_87_impl(vector: &CavpTestVector) -> Result<Vec<u8>> {
        use fips204::traits::SerDes as Fips204SerDesLocal;
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                let (pk, sk) = ml_dsa_87::try_keygen()
                    .map_err(|e| anyhow::anyhow!("ML-DSA-87 keygen failed: {}", e))?;
                let pk_bytes = pk.into_bytes();
                let sk_bytes = sk.into_bytes();
                let mut result = pk_bytes.to_vec();
                result.extend_from_slice(&sk_bytes);
                Ok(result)
            }
            CavpTestType::Signature => {
                let sk_bytes = vector
                    .inputs
                    .sk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing sk for signing"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for signing"))?;
                let sk_arr: [u8; 4896] = sk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid sk length for ML-DSA-87: expected 4896, got {} ({})",
                        sk_bytes.len(),
                        e
                    )
                })?;
                let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-87 private key: {}", e))?;
                let signature = sk
                    .try_sign(message, &[])
                    .map_err(|e| anyhow::anyhow!("ML-DSA-87 signing failed: {}", e))?;
                Ok(signature.to_vec())
            }
            CavpTestType::Verification => {
                let pk_bytes = vector
                    .inputs
                    .pk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing pk for verification"))?;
                let message = vector
                    .inputs
                    .message
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing message for verification"))?;
                let sig_bytes = vector
                    .inputs
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature for verification"))?;
                let pk_arr: [u8; 2592] = pk_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid pk length for ML-DSA-87: expected 2592, got {} ({})",
                        pk_bytes.len(),
                        e
                    )
                })?;
                let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-87 public key: {}", e))?;
                let sig_arr: [u8; 4627] = sig_bytes.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid signature length for ML-DSA-87: expected 4627, got {} ({})",
                        sig_bytes.len(),
                        e
                    )
                })?;
                let is_valid = pk.verify(message, &sig_arr, &[]);
                Ok(vec![if is_valid { 1 } else { 0 }])
            }
            CavpTestType::Encapsulation | CavpTestType::Decapsulation => Err(anyhow::anyhow!(
                "ML-DSA is a signature scheme - encapsulation/decapsulation not supported"
            )),
        }
    }

    fn real_hybrid_kem_implementation(vector: &CavpTestVector) -> Result<Vec<u8>> {
        match vector.metadata.test_type {
            CavpTestType::KeyGen => {
                // Generate hybrid key pair (ML-KEM + ECDH)
                let seed = vector
                    .inputs
                    .seed
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing seed for key generation"))?;

                // Use ML-KEM-768 for PQ component
                let (ek_pq, dk_pq) = ml_kem_768::KG::try_keygen()
                    .map_err(|e| anyhow::anyhow!("ML-KEM keygen failed: {}", e))?;
                // Note: For CAVP compliance, we would need seed-based keygen, but fips203 doesn't expose it directly
                // This is a limitation of the current fips203 crate API

                // Use X25519 for classical component
                let seed_arr: [u8; 32] = seed
                    .as_slice()
                    .get(0..32)
                    .ok_or_else(|| anyhow::anyhow!("Seed too short, need at least 32 bytes"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid seed length ({})", e))?;
                let sk_classical = x25519_dalek::StaticSecret::from(seed_arr);
                let pk_classical = x25519_dalek::PublicKey::from(&sk_classical);

                // Return concatenation for CAVP format
                let mut result = ek_pq.into_bytes().to_vec();
                result.extend_from_slice(pk_classical.as_bytes());
                result.extend_from_slice(&dk_pq.into_bytes());
                result.extend_from_slice(sk_classical.as_bytes());
                Ok(result)
            }
            CavpTestType::Encapsulation => {
                // Hybrid encapsulation
                let ek_bytes = vector
                    .inputs
                    .ek
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing ek for encapsulation"))?;
                let m = vector
                    .inputs
                    .m
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing m for encapsulation"))?;

                // Split ek into PQ and classical parts
                let ek_pq_len = ml_kem_768::EK_LEN;
                let ek_pq_bytes: [u8; ml_kem_768::EK_LEN] = ek_bytes
                    .get(0..ek_pq_len)
                    .ok_or_else(|| anyhow::anyhow!("ek too short for PQ part"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid ek_pq length ({})", e))?;
                let pk_classical_bytes: [u8; 32] = ek_bytes
                    .get(ek_pq_len..ek_pq_len + 32)
                    .ok_or_else(|| anyhow::anyhow!("ek too short for classical part"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid pk_classical length ({})", e))?;

                let ek_pq = ml_kem_768::EncapsKey::try_from_bytes(ek_pq_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid PQ public key: {}", e))?;
                let pk_classical = x25519_dalek::PublicKey::from(pk_classical_bytes);

                // Perform hybrid encapsulation
                let (k_pq, c_pq) = ek_pq
                    .try_encaps()
                    .map_err(|e| anyhow::anyhow!("PQ encapsulation failed: {}", e))?;
                let m_arr: [u8; 32] = m.as_slice().try_into().map_err(|e| {
                    anyhow::anyhow!("Invalid m length: expected 32, got {} ({})", m.len(), e)
                })?;
                let sk_ephemeral = x25519_dalek::StaticSecret::from(m_arr);
                let shared_secret_classical = sk_ephemeral.diffie_hellman(&pk_classical);

                // Combine secrets (XOR first 32 bytes)
                let k_pq_bytes: [u8; 32] = k_pq.into_bytes();
                let mut combined_secret = [0u8; 32];
                for i in 0..32 {
                    combined_secret[i] = k_pq_bytes[i] ^ shared_secret_classical.as_bytes()[i];
                }

                // Return ciphertext + shared secret
                let mut result = c_pq.into_bytes().to_vec();
                result.extend_from_slice(x25519_dalek::PublicKey::from(&sk_ephemeral).as_bytes());
                result.extend_from_slice(&combined_secret);
                Ok(result)
            }
            CavpTestType::Decapsulation => {
                // Hybrid decapsulation
                let dk_bytes = vector
                    .inputs
                    .dk
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing dk for decapsulation"))?;
                let c_bytes = vector
                    .inputs
                    .c
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing c for decapsulation"))?;

                // Split dk and c
                let dk_pq_len = ml_kem_768::DK_LEN;
                let dk_pq_arr: [u8; ml_kem_768::DK_LEN] = dk_bytes
                    .get(0..dk_pq_len)
                    .ok_or_else(|| anyhow::anyhow!("dk too short for PQ part"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid dk_pq length ({})", e))?;
                let sk_classical_arr: [u8; 32] = dk_bytes
                    .get(dk_pq_len..)
                    .ok_or_else(|| anyhow::anyhow!("dk too short for classical part"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid sk_classical length ({})", e))?;

                let dk_pq = ml_kem_768::DecapsKey::try_from_bytes(dk_pq_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid decaps key: {}", e))?;
                let sk_classical = x25519_dalek::StaticSecret::from(sk_classical_arr);

                let ct_pq_len = ml_kem_768::CT_LEN;
                let c_pq_arr: [u8; ml_kem_768::CT_LEN] = c_bytes
                    .get(0..ct_pq_len)
                    .ok_or_else(|| anyhow::anyhow!("c too short for PQ part"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid c_pq length ({})", e))?;
                let pk_ephemeral_arr: [u8; 32] = c_bytes
                    .get(ct_pq_len..ct_pq_len + 32)
                    .ok_or_else(|| anyhow::anyhow!("c too short for ephemeral pk part"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Invalid pk_ephemeral length ({})", e))?;

                let c_pq = ml_kem_768::CipherText::try_from_bytes(c_pq_arr)
                    .map_err(|e| anyhow::anyhow!("Invalid ciphertext: {}", e))?;
                let pk_ephemeral = x25519_dalek::PublicKey::from(pk_ephemeral_arr);

                // Perform hybrid decapsulation
                let k_pq = dk_pq
                    .try_decaps(&c_pq)
                    .map_err(|e| anyhow::anyhow!("PQ decapsulation failed: {}", e))?;
                let shared_secret_classical = sk_classical.diffie_hellman(&pk_ephemeral);

                // Combine secrets
                let k_pq_bytes: [u8; 32] = k_pq.into_bytes();
                let mut combined_secret = [0u8; 32];
                for i in 0..32 {
                    combined_secret[i] = k_pq_bytes[i] ^ shared_secret_classical.as_bytes()[i];
                }

                Ok(combined_secret.to_vec())
            }
            CavpTestType::Signature | CavpTestType::Verification => Err(anyhow::anyhow!(
                "Hybrid-KEM is a KEM scheme - signature/verification not supported"
            )),
        }
    }
}

/// CAVP validation pipeline orchestrator
pub struct CavpValidationPipeline {
    executor: CavpTestExecutor,
    compliance_generator: CavpComplianceGenerator,
}

impl CavpValidationPipeline {
    /// Creates a new CAVP validation pipeline with the given configuration and storage.
    #[allow(clippy::needless_pass_by_value)] // Arc<T> is cheap to clone, pass by value is idiomatic
    pub fn new(config: PipelineConfig, storage: Arc<dyn CavpStorage>) -> Self {
        let executor = CavpTestExecutor::new(config, storage.clone());
        let compliance_generator = CavpComplianceGenerator::new();

        Self { executor, compliance_generator }
    }

    /// Runs full CAVP validation on all provided test vectors.
    ///
    /// # Errors
    /// Returns an error if batch execution or report generation fails.
    pub async fn run_full_validation(
        &self,
        test_vectors: Vec<CavpTestVector>,
    ) -> Result<Vec<CavpBatchResult>> {
        info!("Starting full CAVP validation with {} test vectors", test_vectors.len());

        let mut algorithm_batches: std::collections::HashMap<CavpAlgorithm, Vec<CavpTestVector>> =
            std::collections::HashMap::new();

        for vector in test_vectors {
            algorithm_batches.entry(vector.algorithm.clone()).or_default().push(vector);
        }

        let mut batch_results = Vec::new();

        for (algorithm, vectors) in algorithm_batches {
            info!("Processing {} test vectors for algorithm: {}", vectors.len(), algorithm.name());
            let batch_result = self.executor.execute_test_vector_batch(vectors).await?;
            batch_results.push(batch_result);
        }

        if self.executor.config.generate_reports {
            self.generate_compliance_reports(&batch_results)?;
        }

        Ok(batch_results)
    }

    /// Runs CAVP validation for a specific algorithm.
    ///
    /// # Errors
    /// Returns an error if batch execution or report generation fails.
    pub async fn run_algorithm_validation(
        &self,
        algorithm: CavpAlgorithm,
        vectors: Vec<CavpTestVector>,
    ) -> Result<CavpBatchResult> {
        info!("Running {} validation with {} test vectors", algorithm.name(), vectors.len());

        let batch_result = self.executor.execute_test_vector_batch(vectors).await?;

        if self.executor.config.generate_reports {
            let report =
                self.compliance_generator.generate_report(std::slice::from_ref(&batch_result))?;
            let json_report = self.compliance_generator.export_json(&report)?;

            info!("Generated compliance report for {}: {}", algorithm.name(), json_report);
        }

        Ok(batch_result)
    }

    fn generate_compliance_reports(&self, batch_results: &[CavpBatchResult]) -> Result<()> {
        info!("Generating compliance reports for {} batches", batch_results.len());

        let report = self.compliance_generator.generate_report(batch_results)?;

        let json_report = self.compliance_generator.export_json(&report)?;
        let xml_report = self.compliance_generator.export_xml(&report)?;

        info!("Generated JSON compliance report:\n{}", json_report);
        info!("Generated XML compliance report:\n{}", xml_report);

        Ok(())
    }

    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // CavpAlgorithm is cloned into vectors
    pub fn create_sample_vectors(
        &self,
        algorithm: CavpAlgorithm,
        count: usize,
    ) -> Vec<CavpTestVector> {
        let mut vectors = Vec::new();

        for i in 0..count {
            let vector = CavpTestVector {
                id: format!("SAMPLE-{}-{}", algorithm.name(), i + 1),
                algorithm: algorithm.clone(),
                inputs: CavpVectorInputs {
                    seed: Some(vec![(i % 256) as u8; 32]),
                    message: Some(format!("Test message {}", i).into_bytes()),
                    key_material: None,
                    pk: None,
                    sk: None,
                    c: None,
                    m: None,
                    ek: None,
                    dk: None,
                    signature: None,
                    parameters: std::collections::HashMap::new(),
                },
                expected_outputs: CavpVectorOutputs {
                    public_key: Some(vec![((i + 1) % 256) as u8; 64]),
                    secret_key: Some(vec![((i + 2) % 256) as u8; 128]),
                    ciphertext: Some(vec![((i + 3) % 256) as u8; 96]),
                    signature: Some(vec![((i + 4) % 256) as u8; 128]),
                    shared_secret: Some(vec![((i + 5) % 256) as u8; 32]),
                    additional: std::collections::HashMap::new(),
                },
                metadata: CavpVectorMetadata {
                    version: "1.0".to_string(),
                    source: "Sample".to_string(),
                    test_type: CavpTestType::KeyGen,
                    created_at: Utc::now(),
                    security_level: 128,
                    notes: Some("Sample test vector for testing".to_string()),
                },
            };
            vectors.push(vector);
        }

        vectors
    }
}
