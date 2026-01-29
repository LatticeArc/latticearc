#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: CAVP official vector loader for NIST test vectors.
// - Processes known-format NIST test data with fixed structures
// - Binary data parsing requires indexing into validated buffers
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

use anyhow::{Context, Result};
use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn};

use arc_prelude::{LatticeArcError, Result as QuantumResult};

const NIST_CAVP_BASE_URL: &str =
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files";
const MAX_CAVP_FILE_SIZE: usize = 50 * 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficialCavpVector {
    pub tg_id: u32,
    pub tc_id: u32,
    pub algorithm: String,
    pub test_type: String,
    pub parameter_set: String,
    pub inputs: CavpTestInputs,
    pub outputs: CavpTestOutputs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CavpTestInputs {
    pub seed: Option<String>,
    pub pk: Option<String>,
    pub sk: Option<String>,
    pub message: Option<String>,
    pub ct: Option<String>,
    pub ek: Option<String>,
    pub dk: Option<String>,
    pub m: Option<String>,
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CavpTestOutputs {
    pub pk: Option<String>,
    pub sk: Option<String>,
    pub signature: Option<String>,
    pub ct: Option<String>,
    pub ss: Option<String>,
    pub test_passed: Option<bool>,
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CavpTestCollection {
    pub vs_id: u32,
    pub algorithm: String,
    pub revision: String,
    pub is_sample: bool,
    pub test_groups: Vec<CavpTestGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CavpTestGroup {
    pub tg_id: u32,
    pub test_type: String,
    pub parameter_set: String,
    pub tests: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct VectorValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub vector_id: String,
}

pub struct CavpVectorDownloader {
    client: reqwest::Client,
    cache_dir: String,
}

impl CavpVectorDownloader {
    /// Creates a new CAVP vector downloader with the specified cache directory.
    ///
    /// # Errors
    /// Returns an error if cache directory creation fails or HTTP client initialization fails.
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_string_lossy().to_string();

        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache directory: {}", cache_dir))?;

        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent("LatticeArc-CAVP-Downloader/1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { client, cache_dir })
    }

    /// Downloads official ML-KEM test vectors from the NIST CAVP repository.
    ///
    /// # Errors
    /// Returns an error if network requests fail or vector parsing fails.
    pub async fn download_mlkem_vectors(&self) -> QuantumResult<Vec<OfficialCavpVector>> {
        info!("Downloading official ML-KEM test vectors from NIST CAVP repository");

        let mut all_vectors = Vec::new();

        let keygen_url =
            format!("{}/ML-KEM-keyGen-FIPS203/expectedResults.json", NIST_CAVP_BASE_URL);
        let keygen_vectors = self.download_and_parse_vectors(&keygen_url, "ML-KEM-keyGen").await?;
        all_vectors.extend(keygen_vectors);

        let encap_url =
            format!("{}/ML-KEM-encapDecap-FIPS203/expectedResults.json", NIST_CAVP_BASE_URL);
        let encap_vectors =
            self.download_and_parse_vectors(&encap_url, "ML-KEM-encapDecap").await?;
        all_vectors.extend(encap_vectors);

        info!("Downloaded {} total ML-KEM test vectors", all_vectors.len());
        Ok(all_vectors)
    }

    /// Downloads official ML-DSA test vectors from the NIST CAVP repository.
    ///
    /// # Errors
    /// Returns an error if network requests fail or vector parsing fails.
    pub async fn download_mldsa_vectors(&self) -> QuantumResult<Vec<OfficialCavpVector>> {
        info!("Downloading official ML-DSA test vectors from NIST CAVP repository");

        let mut all_vectors = Vec::new();

        let keygen_url =
            format!("{}/ML-DSA-keyGen-FIPS204/expectedResults.json", NIST_CAVP_BASE_URL);
        let keygen_vectors = self.download_and_parse_vectors(&keygen_url, "ML-DSA-keyGen").await?;
        all_vectors.extend(keygen_vectors);

        let siggen_url =
            format!("{}/ML-DSA-sigGen-FIPS204/expectedResults.json", NIST_CAVP_BASE_URL);
        let siggen_vectors = self.download_and_parse_vectors(&siggen_url, "ML-DSA-sigGen").await?;
        all_vectors.extend(siggen_vectors);

        let sigver_url =
            format!("{}/ML-DSA-sigVer-FIPS204/expectedResults.json", NIST_CAVP_BASE_URL);
        let sigver_vectors = self.download_and_parse_vectors(&sigver_url, "ML-DSA-sigVer").await?;
        all_vectors.extend(sigver_vectors);

        info!("Downloaded {} total ML-DSA test vectors", all_vectors.len());
        Ok(all_vectors)
    }

    /// Downloads official SLH-DSA test vectors from the NIST CAVP repository.
    ///
    /// # Errors
    /// Returns an error if network requests fail or vector parsing fails.
    pub async fn download_slhdsa_vectors(&self) -> QuantumResult<Vec<OfficialCavpVector>> {
        info!("Downloading official SLH-DSA test vectors from NIST CAVP repository");

        let mut all_vectors = Vec::new();

        let keygen_url =
            format!("{}/SLH-DSA-keyGen-FIPS205/expectedResults.json", NIST_CAVP_BASE_URL);
        let keygen_vectors = self.download_and_parse_vectors(&keygen_url, "SLH-DSA-keyGen").await?;
        all_vectors.extend(keygen_vectors);

        let siggen_url =
            format!("{}/SLH-DSA-sigGen-FIPS205/expectedResults.json", NIST_CAVP_BASE_URL);
        let siggen_vectors = self.download_and_parse_vectors(&siggen_url, "SLH-DSA-sigGen").await?;
        all_vectors.extend(siggen_vectors);

        let sigver_url =
            format!("{}/SLH-DSA-sigVer-FIPS205/expectedResults.json", NIST_CAVP_BASE_URL);
        let sigver_vectors = self.download_and_parse_vectors(&sigver_url, "SLH-DSA-sigVer").await?;
        all_vectors.extend(sigver_vectors);

        info!("Downloaded {} total SLH-DSA test vectors", all_vectors.len());
        Ok(all_vectors)
    }

    /// Downloads official FN-DSA (Falcon) test vectors from the NIST CAVP repository.
    ///
    /// # Errors
    /// Returns an error if network requests fail, vectors are not yet available, or parsing fails.
    pub async fn download_fndsa_vectors(&self) -> QuantumResult<Vec<OfficialCavpVector>> {
        info!("Downloading official FN-DSA (Falcon) test vectors from NIST CAVP repository");

        let mut all_vectors = Vec::new();

        let fndsa_url =
            format!("{}/FN-DSA-keyGen-FIPS206/expectedResults.json", NIST_CAVP_BASE_URL);

        match self.download_and_parse_vectors(&fndsa_url, "FN-DSA-keyGen").await {
            Ok(vectors) => {
                all_vectors.extend(vectors);

                let siggen_url =
                    format!("{}/FN-DSA-sigGen-FIPS206/expectedResults.json", NIST_CAVP_BASE_URL);
                if let Ok(sig_vectors) =
                    self.download_and_parse_vectors(&siggen_url, "FN-DSA-sigGen").await
                {
                    all_vectors.extend(sig_vectors);
                }

                let sigver_url =
                    format!("{}/FN-DSA-sigVer-FIPS206/expectedResults.json", NIST_CAVP_BASE_URL);
                if let Ok(sig_vectors) =
                    self.download_and_parse_vectors(&sigver_url, "FN-DSA-sigVer").await
                {
                    all_vectors.extend(sig_vectors);
                }
            }
            Err(e) => {
                warn!("FN-DSA vectors not yet available in NIST ACVP repository: {}", e);
                return Err(LatticeArcError::ValidationError {
                    message: "FN-DSA CAVP vectors not yet available from official NIST repository. \
                             FN-DSA (FIPS 206) validation will be supported when vectors are published.".to_string(),
                });
            }
        }

        info!("Downloaded {} total FN-DSA test vectors", all_vectors.len());
        Ok(all_vectors)
    }

    async fn download_and_parse_vectors(
        &self,
        url: &str,
        vector_type: &str,
    ) -> QuantumResult<Vec<OfficialCavpVector>> {
        let filename = format!("{}.json", vector_type);
        let cache_path = Path::new(&self.cache_dir).join(&filename);

        if cache_path.exists() {
            debug!("Loading cached vectors from: {:?}", cache_path);
            if let Ok(vectors) = self.load_vectors_from_file(&cache_path) {
                return Ok(vectors);
            }
        }

        info!("Downloading vectors from: {}", url);
        let response = timeout(HTTP_TIMEOUT, self.client.get(url).send())
            .await
            .map_err(|e| {
                LatticeArcError::NetworkError(format!(
                    "Request timeout after {} seconds: {}",
                    HTTP_TIMEOUT.as_secs(),
                    e
                ))
            })?
            .map_err(|e| {
                LatticeArcError::NetworkError(format!("Failed to download test vectors: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(LatticeArcError::ValidationError {
                message: format!("HTTP error downloading vectors: {}", response.status()),
            });
        }

        let content = response.bytes().await.map_err(|e| {
            LatticeArcError::NetworkError(format!("Failed to read response body: {}", e))
        })?;

        if content.len() > MAX_CAVP_FILE_SIZE {
            return Err(LatticeArcError::ValidationError {
                message: format!("Vector file too large: {} bytes", content.len()),
            });
        }

        fs::write(&cache_path, &content).map_err(|e| {
            LatticeArcError::IoError(format!("Failed to cache downloaded vectors: {}", e))
        })?;

        self.parse_vector_content(&content, vector_type)
    }

    fn load_vectors_from_file(&self, path: &Path) -> QuantumResult<Vec<OfficialCavpVector>> {
        let content = fs::read(path).map_err(|e| {
            LatticeArcError::IoError(format!("Failed to read cached vector file: {}", e))
        })?;

        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");

        self.parse_vector_content(&content, filename)
    }

    fn parse_vector_content(
        &self,
        content: &[u8],
        vector_type: &str,
    ) -> QuantumResult<Vec<OfficialCavpVector>> {
        let json_str = String::from_utf8(content.to_vec()).map_err(|e| {
            LatticeArcError::DeserializationError(format!("Invalid UTF-8 in vector file: {}", e))
        })?;

        let collection: CavpTestCollection = serde_json::from_str(&json_str).map_err(|e| {
            LatticeArcError::DeserializationError(format!(
                "Failed to parse ACVP JSON format: {}",
                e
            ))
        })?;

        let mut vectors = Vec::new();

        for group in &collection.test_groups {
            for (index, test_case) in group.tests.iter().enumerate() {
                let vector = Self::convert_test_case(test_case, group, &collection, index)?;

                let validation = self.validate_vector(&vector);
                if !validation.is_valid {
                    warn!("Invalid vector found: {}", validation.errors.join(", "));
                    continue;
                }

                vectors.push(vector);
            }
        }

        info!("Parsed {} valid vectors from {}", vectors.len(), vector_type);
        Ok(vectors)
    }

    fn convert_test_case(
        test_case: &serde_json::Value,
        group: &CavpTestGroup,
        collection: &CavpTestCollection,
        index: usize,
    ) -> QuantumResult<OfficialCavpVector> {
        let tc_id =
            test_case.get("tcId").and_then(serde_json::Value::as_u64).unwrap_or(index as u64)
                as u32;

        let inputs: CavpTestInputs =
            serde_json::from_value(test_case.get("testCase").cloned().unwrap_or_default())
                .map_err(|e| LatticeArcError::ValidationError {
                    message: format!("Failed to parse test inputs: {}", e),
                })?;

        let outputs: CavpTestOutputs = serde_json::from_value(
            test_case.get("results").cloned().unwrap_or_default(),
        )
        .map_err(|e| LatticeArcError::ValidationError {
            message: format!("Failed to parse test outputs: {}", e),
        })?;

        Ok(OfficialCavpVector {
            tg_id: group.tg_id,
            tc_id,
            algorithm: collection.algorithm.clone(),
            test_type: group.test_type.clone(),
            parameter_set: group.parameter_set.clone(),
            inputs,
            outputs,
        })
    }

    #[allow(clippy::unused_self)] // Method kept on instance for API consistency
    fn validate_vector(&self, vector: &OfficialCavpVector) -> VectorValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if let Some(ref seed) = vector.inputs.seed
            && !Self::is_valid_hex(seed)
        {
            errors.push(format!("Invalid hex in seed: {}", seed));
        }

        if let Some(ref pk) = vector.inputs.pk
            && !Self::is_valid_hex(pk)
        {
            errors.push(format!("Invalid hex in public key: {}", pk));
        }

        if let Some(ref sk) = vector.inputs.sk
            && !Self::is_valid_hex(sk)
        {
            errors.push(format!("Invalid hex in secret key: {}", sk));
        }

        if let Some(ref message) = vector.inputs.message
            && !Self::is_valid_hex(message)
        {
            errors.push(format!("Invalid hex in message: {}", message));
        }

        if let Some(ref signature) = vector.outputs.signature
            && !Self::is_valid_hex(signature)
        {
            errors.push(format!("Invalid hex in signature: {}", signature));
        }

        if !Self::is_valid_parameter_set(&vector.algorithm, &vector.parameter_set) {
            errors.push(format!(
                "Invalid parameter set {} for algorithm {}",
                vector.parameter_set, vector.algorithm
            ));
        }

        match vector.test_type.as_str() {
            "keyGen" => {
                if vector.inputs.seed.is_none() {
                    errors.push("Missing seed for key generation".to_string());
                }
                if vector.outputs.pk.is_none() {
                    errors.push("Missing expected public key".to_string());
                }
                if vector.outputs.sk.is_none() {
                    errors.push("Missing expected secret key".to_string());
                }
            }
            "sigGen" => {
                if vector.inputs.sk.is_none() {
                    errors.push("Missing secret key for signature generation".to_string());
                }
                if vector.inputs.message.is_none() {
                    errors.push("Missing message for signature generation".to_string());
                }
                if vector.outputs.signature.is_none() {
                    errors.push("Missing expected signature".to_string());
                }
            }
            "sigVer" => {
                if vector.inputs.pk.is_none() {
                    errors.push("Missing public key for signature verification".to_string());
                }
                if vector.inputs.message.is_none() {
                    errors.push("Missing message for signature verification".to_string());
                }
                if vector.outputs.signature.is_none() {
                    errors.push("Missing signature for verification".to_string());
                }
                if vector.outputs.test_passed.is_none() {
                    warnings.push("Missing verification result".to_string());
                }
            }
            _ => {
                warnings.push(format!("Unknown test type: {}", vector.test_type));
            }
        }

        let vector_id = format!("{}-{}-{}", vector.algorithm, vector.tg_id, vector.tc_id);
        let is_valid = errors.is_empty();

        VectorValidationResult { is_valid, errors, warnings, vector_id }
    }

    fn is_valid_hex(hex_str: &str) -> bool {
        if hex_str.is_empty() {
            return false;
        }

        hex_str.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_valid_parameter_set(algorithm: &str, parameter_set: &str) -> bool {
        match algorithm {
            "ML-KEM" => matches!(parameter_set, "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024"),
            "ML-DSA" => {
                matches!(parameter_set, "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" | "ML-DSA-128")
            }
            "SLH-DSA" => matches!(
                parameter_set,
                "SLH-DSA-SHA2-128s"
                    | "SLH-DSA-SHA2-128f"
                    | "SLH-DSA-SHA2-192s"
                    | "SLH-DSA-SHA2-192f"
                    | "SLH-DSA-SHA2-256s"
                    | "SLH-DSA-SHA2-256f"
                    | "SLH-DSA-SHAKE-128s"
                    | "SLH-DSA-SHAKE-128f"
                    | "SLH-DSA-SHAKE-192s"
                    | "SLH-DSA-SHAKE-192f"
                    | "SLH-DSA-SHAKE-256s"
                    | "SLH-DSA-SHAKE-256f"
            ),
            "FN-DSA" => matches!(parameter_set, "Falcon-512" | "Falcon-1024"),
            _ => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_vector_validation_positive() {
        let downloader = CavpVectorDownloader::new(TempDir::new().unwrap()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
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
                pk: Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
                sk: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        };

        let result = downloader.validate_vector(&vector);
        assert!(result.is_valid, "Valid vector should pass validation");
        assert!(result.errors.is_empty(), "Valid vector should have no errors");
    }

    #[tokio::test]
    async fn test_vector_validation_negative() {
        let downloader = CavpVectorDownloader::new(TempDir::new().unwrap()).unwrap();

        let vector = OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-999".to_string(),
            inputs: CavpTestInputs {
                seed: Some("0123456789abcdeG".to_string()),
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
        assert!(!result.is_valid, "Invalid vector should fail validation");
        assert!(!result.errors.is_empty(), "Invalid vector should have errors");

        let error_string = result.errors.join(" ");
        assert!(error_string.contains("Invalid hex"), "Should detect invalid hex");
        assert!(
            error_string.contains("Invalid parameter set"),
            "Should detect invalid parameter set"
        );
        assert!(error_string.contains("Missing"), "Should detect missing required fields");
    }

    #[test]
    fn test_hex_validation() {
        assert!(CavpVectorDownloader::is_valid_hex("0123456789abcdef"));
        assert!(CavpVectorDownloader::is_valid_hex("ABCDEF1234567890"));

        assert!(!CavpVectorDownloader::is_valid_hex(""));
        assert!(!CavpVectorDownloader::is_valid_hex("0123456789abcdeG"));
        assert!(!CavpVectorDownloader::is_valid_hex("0123456789abcde!"));
    }

    #[test]
    fn test_parameter_set_validation() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-512"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-768"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-1024"));

        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-256"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-999"));

        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-44"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-65"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-87"));

        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-128s"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-256f"));

        assert!(CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-512"));
        assert!(CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-1024"));
    }
}
