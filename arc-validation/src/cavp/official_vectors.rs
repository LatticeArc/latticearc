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

    /// Loads vectors from a cached file.
    ///
    /// # Errors
    /// Returns an error if file reading or parsing fails.
    pub fn load_vectors_from_file(&self, path: &Path) -> QuantumResult<Vec<OfficialCavpVector>> {
        let content = fs::read(path).map_err(|e| {
            LatticeArcError::IoError(format!("Failed to read cached vector file: {}", e))
        })?;

        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");

        self.parse_vector_content(&content, filename)
    }

    /// Parses vector content from raw bytes.
    ///
    /// # Errors
    /// Returns an error if UTF-8 decoding or JSON parsing fails.
    pub fn parse_vector_content(
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

    /// Validates a CAVP test vector for correctness.
    ///
    /// Checks hex encoding, parameter sets, and required fields based on test type.
    #[must_use]
    #[allow(clippy::unused_self)] // Method kept on instance for API consistency
    pub fn validate_vector(&self, vector: &OfficialCavpVector) -> VectorValidationResult {
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

    /// Validates that a string contains only valid hexadecimal characters.
    #[must_use]
    pub fn is_valid_hex(hex_str: &str) -> bool {
        if hex_str.is_empty() {
            return false;
        }

        hex_str.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validates that a parameter set is valid for the given algorithm.
    #[must_use]
    pub fn is_valid_parameter_set(algorithm: &str, parameter_set: &str) -> bool {
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
#[allow(dead_code)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // ========================================================================
    // Test helpers
    // ========================================================================

    fn make_downloader() -> (TempDir, CavpVectorDownloader) {
        let tmp = TempDir::new().unwrap();
        let dl = CavpVectorDownloader::new(tmp.path()).unwrap();
        (tmp, dl)
    }

    fn make_default_inputs() -> CavpTestInputs {
        CavpTestInputs {
            seed: None,
            pk: None,
            sk: None,
            message: None,
            ct: None,
            ek: None,
            dk: None,
            m: None,
            additional: HashMap::new(),
        }
    }

    fn make_default_outputs() -> CavpTestOutputs {
        CavpTestOutputs {
            pk: None,
            sk: None,
            signature: None,
            ct: None,
            ss: None,
            test_passed: None,
            additional: HashMap::new(),
        }
    }

    fn make_vector(
        algorithm: &str,
        test_type: &str,
        parameter_set: &str,
        inputs: CavpTestInputs,
        outputs: CavpTestOutputs,
    ) -> OfficialCavpVector {
        OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: algorithm.to_string(),
            test_type: test_type.to_string(),
            parameter_set: parameter_set.to_string(),
            inputs,
            outputs,
        }
    }

    fn make_collection_json(algorithm: &str, groups: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "vs_id": 1,
            "algorithm": algorithm,
            "revision": "1.0",
            "is_sample": true,
            "test_groups": groups
        })
    }

    fn make_group_json(
        tg_id: u32,
        test_type: &str,
        parameter_set: &str,
        tests: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        json!({
            "tg_id": tg_id,
            "test_type": test_type,
            "parameter_set": parameter_set,
            "tests": tests
        })
    }

    // ========================================================================
    // Existing tests (preserved)
    // ========================================================================

    #[tokio::test]
    async fn test_vector_validation_positive() {
        let (_tmp, downloader) = make_downloader();

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
        let (_tmp, downloader) = make_downloader();

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

    // ========================================================================
    // is_valid_hex - edge cases
    // ========================================================================

    #[test]
    fn test_hex_single_valid_chars() {
        for c in "0123456789abcdefABCDEF".chars() {
            assert!(
                CavpVectorDownloader::is_valid_hex(&c.to_string()),
                "Expected '{}' to be valid hex",
                c
            );
        }
    }

    #[test]
    fn test_hex_invalid_chars_just_outside_range() {
        // Characters adjacent to hex range that should be rejected
        assert!(!CavpVectorDownloader::is_valid_hex("g"));
        assert!(!CavpVectorDownloader::is_valid_hex("G"));
        assert!(!CavpVectorDownloader::is_valid_hex("z"));
        assert!(!CavpVectorDownloader::is_valid_hex("Z"));
    }

    #[test]
    fn test_hex_whitespace_rejected() {
        assert!(!CavpVectorDownloader::is_valid_hex(" "));
        assert!(!CavpVectorDownloader::is_valid_hex("ab cd"));
        assert!(!CavpVectorDownloader::is_valid_hex("ab\tcd"));
        assert!(!CavpVectorDownloader::is_valid_hex("ab\ncd"));
    }

    #[test]
    fn test_hex_prefix_rejected() {
        // "0x" prefix is not valid raw hex
        assert!(!CavpVectorDownloader::is_valid_hex("0x1234"));
    }

    // ========================================================================
    // is_valid_parameter_set - exhaustive coverage
    // ========================================================================

    #[test]
    fn test_parameter_set_mldsa_128() {
        assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-128"));
    }

    #[test]
    fn test_parameter_set_slhdsa_all_sha2_variants() {
        let valid = [
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
        ];
        for ps in &valid {
            assert!(
                CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", ps),
                "Expected SLH-DSA / {} to be valid",
                ps
            );
        }
    }

    #[test]
    fn test_parameter_set_slhdsa_all_shake_variants() {
        let valid = [
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ];
        for ps in &valid {
            assert!(
                CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", ps),
                "Expected SLH-DSA / {} to be valid",
                ps
            );
        }
    }

    #[test]
    fn test_parameter_set_slhdsa_invalid_combo() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-384f"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-384s"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "ML-KEM-768"));
    }

    #[test]
    fn test_parameter_set_fndsa_invalid() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-256"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-2048"));
    }

    #[test]
    fn test_parameter_set_unknown_algorithm() {
        assert!(!CavpVectorDownloader::is_valid_parameter_set("UNKNOWN", "any-value"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("", ""));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("AES", "AES-256"));
    }

    #[test]
    fn test_parameter_set_cross_algorithm() {
        // Valid set for a different algorithm should fail
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-DSA-44"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-KEM-512"));
        assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "ML-KEM-768"));
    }

    // ========================================================================
    // validate_vector - sigGen test type
    // ========================================================================

    #[test]
    fn test_validate_siggen_valid() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-65",
            CavpTestInputs {
                sk: Some("aabbccdd".to_string()),
                message: Some("001122".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { signature: Some("deadbeef".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(r.is_valid);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn test_validate_siggen_missing_sk() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-44",
            CavpTestInputs { message: Some("001122".to_string()), ..make_default_inputs() },
            CavpTestOutputs { signature: Some("deadbeef".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing secret key")));
    }

    #[test]
    fn test_validate_siggen_missing_message() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-44",
            CavpTestInputs { sk: Some("aabbcc".to_string()), ..make_default_inputs() },
            CavpTestOutputs { signature: Some("deadbeef".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing message for signature generation")));
    }

    #[test]
    fn test_validate_siggen_missing_signature() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-44",
            CavpTestInputs {
                sk: Some("aabbcc".to_string()),
                message: Some("001122".to_string()),
                ..make_default_inputs()
            },
            make_default_outputs(),
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing expected signature")));
    }

    // ========================================================================
    // validate_vector - sigVer test type
    // ========================================================================

    #[test]
    fn test_validate_sigver_valid() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-87",
            CavpTestInputs {
                pk: Some("aabbccdd".to_string()),
                message: Some("001122".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs {
                signature: Some("deadbeef".to_string()),
                test_passed: Some(true),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(r.is_valid);
    }

    #[test]
    fn test_validate_sigver_missing_pk() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            CavpTestInputs { message: Some("001122".to_string()), ..make_default_inputs() },
            CavpTestOutputs {
                signature: Some("deadbeef".to_string()),
                test_passed: Some(false),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing public key")));
    }

    #[test]
    fn test_validate_sigver_missing_message() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            CavpTestInputs { pk: Some("aabb".to_string()), ..make_default_inputs() },
            CavpTestOutputs {
                signature: Some("deadbeef".to_string()),
                test_passed: Some(true),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing message for signature verification")));
    }

    #[test]
    fn test_validate_sigver_missing_signature() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            CavpTestInputs {
                pk: Some("aabb".to_string()),
                message: Some("0011".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { test_passed: Some(true), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing signature for verification")));
    }

    #[test]
    fn test_validate_sigver_missing_test_passed_gives_warning() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            CavpTestInputs {
                pk: Some("aabb".to_string()),
                message: Some("0011".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { signature: Some("deadbeef".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        // Still valid but has a warning
        assert!(r.is_valid);
        assert!(r.warnings.iter().any(|w| w.contains("Missing verification result")));
    }

    #[test]
    fn test_validate_sigver_with_test_passed_false() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            CavpTestInputs {
                pk: Some("aabb".to_string()),
                message: Some("0011".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs {
                signature: Some("deadbeef".to_string()),
                test_passed: Some(false),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(r.is_valid);
        assert!(r.warnings.is_empty());
    }

    // ========================================================================
    // validate_vector - keyGen test type
    // ========================================================================

    #[test]
    fn test_validate_keygen_missing_seed() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-512",
            make_default_inputs(),
            CavpTestOutputs {
                pk: Some("aabb".to_string()),
                sk: Some("ccdd".to_string()),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing seed")));
    }

    #[test]
    fn test_validate_keygen_missing_output_pk() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-512",
            CavpTestInputs { seed: Some("aabb".to_string()), ..make_default_inputs() },
            CavpTestOutputs { sk: Some("ccdd".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing expected public key")));
    }

    #[test]
    fn test_validate_keygen_missing_output_sk() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-512",
            CavpTestInputs { seed: Some("aabb".to_string()), ..make_default_inputs() },
            CavpTestOutputs { pk: Some("ccdd".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Missing expected secret key")));
    }

    // ========================================================================
    // validate_vector - unknown test type
    // ========================================================================

    #[test]
    fn test_validate_unknown_test_type_gives_warning() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "encapDecap",
            "ML-KEM-768",
            CavpTestInputs { seed: Some("aabb".to_string()), ..make_default_inputs() },
            make_default_outputs(),
        );
        let r = dl.validate_vector(&v);
        // Unknown test type produces a warning, not an error, but missing required
        // parameter set validation may still cause errors depending on logic.
        assert!(r.warnings.iter().any(|w| w.contains("Unknown test type")));
    }

    // ========================================================================
    // validate_vector - invalid hex in various input/output fields
    // ========================================================================

    #[test]
    fn test_validate_invalid_hex_in_input_pk() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            CavpTestInputs {
                pk: Some("not_hex!".to_string()),
                message: Some("aabb".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs {
                signature: Some("aabb".to_string()),
                test_passed: Some(true),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Invalid hex in public key")));
    }

    #[test]
    fn test_validate_invalid_hex_in_input_sk() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-44",
            CavpTestInputs {
                sk: Some("xyz".to_string()),
                message: Some("aabb".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { signature: Some("aabb".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Invalid hex in secret key")));
    }

    #[test]
    fn test_validate_invalid_hex_in_input_message() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-44",
            CavpTestInputs {
                sk: Some("aabb".to_string()),
                message: Some("zzzz".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { signature: Some("aabb".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Invalid hex in message")));
    }

    #[test]
    fn test_validate_invalid_hex_in_output_signature() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-44",
            CavpTestInputs {
                sk: Some("aabb".to_string()),
                message: Some("ccdd".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs {
                signature: Some("!!invalid!!".to_string()),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.iter().any(|e| e.contains("Invalid hex in signature")));
    }

    #[test]
    fn test_validate_all_hex_fields_invalid_at_once() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-768",
            CavpTestInputs {
                seed: Some("GHIJ".to_string()),
                pk: Some("!!".to_string()),
                sk: Some("@@".to_string()),
                message: Some("~~".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs {
                signature: Some("%%".to_string()),
                pk: Some("aabb".to_string()),
                sk: Some("ccdd".to_string()),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        // Should have errors for seed, pk, sk, message, and signature
        assert!(r.errors.len() >= 5);
    }

    // ========================================================================
    // validate_vector - vector_id format
    // ========================================================================

    #[test]
    fn test_vector_id_format() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-768",
            CavpTestInputs { seed: Some("aabb".to_string()), ..make_default_inputs() },
            CavpTestOutputs {
                pk: Some("ccdd".to_string()),
                sk: Some("eeff".to_string()),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert_eq!(r.vector_id, "ML-KEM-1-1");
    }

    #[test]
    fn test_vector_id_with_different_ids() {
        let (_tmp, dl) = make_downloader();
        let mut v = make_vector(
            "SLH-DSA",
            "keyGen",
            "SLH-DSA-SHA2-128s",
            CavpTestInputs { seed: Some("aabb".to_string()), ..make_default_inputs() },
            CavpTestOutputs {
                pk: Some("ccdd".to_string()),
                sk: Some("eeff".to_string()),
                ..make_default_outputs()
            },
        );
        v.tg_id = 42;
        v.tc_id = 99;
        let r = dl.validate_vector(&v);
        assert_eq!(r.vector_id, "SLH-DSA-42-99");
    }

    // ========================================================================
    // convert_test_case - direct tests of private method
    // ========================================================================

    #[test]
    fn test_convert_test_case_with_valid_keygen() {
        let test_case = json!({
            "tcId": 5,
            "testCase": {
                "seed": "aabbccdd"
            },
            "results": {
                "pk": "11223344",
                "sk": "55667788"
            }
        });
        let group = CavpTestGroup {
            tg_id: 10,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 100,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 0);
        assert!(result.is_ok());
        let vector = result.unwrap();
        assert_eq!(vector.tc_id, 5);
        assert_eq!(vector.tg_id, 10);
        assert_eq!(vector.algorithm, "ML-KEM");
        assert_eq!(vector.test_type, "keyGen");
        assert_eq!(vector.parameter_set, "ML-KEM-768");
        assert_eq!(vector.inputs.seed, Some("aabbccdd".to_string()));
        assert_eq!(vector.outputs.pk, Some("11223344".to_string()));
        assert_eq!(vector.outputs.sk, Some("55667788".to_string()));
    }

    #[test]
    fn test_convert_test_case_without_tcid_uses_index() {
        let test_case = json!({
            "testCase": {
                "seed": "aabb"
            },
            "results": {
                "pk": "ccdd",
                "sk": "eeff"
            }
        });
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-512".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 1,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: false,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 7);
        assert!(result.is_ok());
        let vector = result.unwrap();
        assert_eq!(vector.tc_id, 7);
    }

    #[test]
    fn test_convert_test_case_tcid_as_string_uses_index() {
        let test_case = json!({
            "tcId": "not_a_number",
            "testCase": { "seed": "aa" },
            "results": { "pk": "bb", "sk": "cc" }
        });
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 1,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().tc_id, 3);
    }

    #[test]
    fn test_convert_test_case_missing_testcase_field_uses_default() {
        // When "testCase" is absent, unwrap_or_default gives Value::Null,
        // which deserializes to an empty CavpTestInputs (all None).
        let test_case = json!({
            "tcId": 1,
            "results": { "pk": "aabb", "sk": "ccdd" }
        });
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 1,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        // serde_json::from_value(Value::Null) for CavpTestInputs may fail because
        // Null is not an object. Let's verify the actual behavior.
        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 0);
        // The implementation does .get("testCase").cloned().unwrap_or_default()
        // Value::default() is Value::Null, and from_value(Null) for a struct fails.
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_test_case_missing_results_field_uses_default() {
        let test_case = json!({
            "tcId": 1,
            "testCase": { "seed": "aabb" }
        });
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 1,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_test_case_with_siggen_data() {
        let test_case = json!({
            "tcId": 42,
            "testCase": {
                "sk": "aabbccdd",
                "message": "11223344"
            },
            "results": {
                "signature": "deadbeef"
            }
        });
        let group = CavpTestGroup {
            tg_id: 2,
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-65".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 200,
            algorithm: "ML-DSA".to_string(),
            revision: "2.0".to_string(),
            is_sample: false,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 0);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.tc_id, 42);
        assert_eq!(v.tg_id, 2);
        assert_eq!(v.algorithm, "ML-DSA");
        assert_eq!(v.test_type, "sigGen");
        assert_eq!(v.inputs.sk, Some("aabbccdd".to_string()));
        assert_eq!(v.inputs.message, Some("11223344".to_string()));
        assert_eq!(v.outputs.signature, Some("deadbeef".to_string()));
    }

    #[test]
    fn test_convert_test_case_with_sigver_data() {
        let test_case = json!({
            "tcId": 7,
            "testCase": {
                "pk": "aabb",
                "message": "ccdd"
            },
            "results": {
                "signature": "eeff",
                "test_passed": false
            }
        });
        let group = CavpTestGroup {
            tg_id: 3,
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 300,
            algorithm: "ML-DSA".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 0);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.tc_id, 7);
        assert_eq!(v.inputs.pk, Some("aabb".to_string()));
        assert_eq!(v.inputs.message, Some("ccdd".to_string()));
        assert_eq!(v.outputs.signature, Some("eeff".to_string()));
        assert_eq!(v.outputs.test_passed, Some(false));
    }

    #[test]
    fn test_convert_test_case_with_extra_fields() {
        let test_case = json!({
            "tcId": 1,
            "testCase": {
                "seed": "aabb",
                "customField": "custom_value"
            },
            "results": {
                "pk": "ccdd",
                "sk": "eeff",
                "extraOutput": 42
            }
        });
        let group = CavpTestGroup {
            tg_id: 1,
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            tests: vec![],
        };
        let collection = CavpTestCollection {
            vs_id: 1,
            algorithm: "ML-KEM".to_string(),
            revision: "1.0".to_string(),
            is_sample: true,
            test_groups: vec![],
        };

        let result = CavpVectorDownloader::convert_test_case(&test_case, &group, &collection, 0);
        assert!(result.is_ok());
        let v = result.unwrap();
        // Extra fields should be captured in the additional map via #[serde(flatten)]
        assert!(v.inputs.additional.contains_key("customField"));
        assert!(v.outputs.additional.contains_key("extraOutput"));
    }

    // ========================================================================
    // parse_vector_content - comprehensive coverage
    // ========================================================================

    #[test]
    fn test_parse_vector_content_valid_keygen() {
        let (_tmp, dl) = make_downloader();
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-768",
            vec![
                json!({
                    "tcId": 1,
                    "testCase": { "seed": "aabb" },
                    "results": { "pk": "ccdd", "sk": "eeff" }
                }),
                json!({
                    "tcId": 2,
                    "testCase": { "seed": "1122" },
                    "results": { "pk": "3344", "sk": "5566" }
                }),
            ],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 2);
    }

    #[test]
    fn test_parse_vector_content_skips_invalid_vectors() {
        let (_tmp, dl) = make_downloader();
        // Mix of valid and invalid vectors: one with invalid hex, one valid
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-768",
            vec![
                json!({
                    "tcId": 1,
                    "testCase": { "seed": "GHIJ" },
                    "results": { "pk": "ccdd", "sk": "eeff" }
                }),
                json!({
                    "tcId": 2,
                    "testCase": { "seed": "aabb" },
                    "results": { "pk": "ccdd", "sk": "eeff" }
                }),
            ],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_ok());
        let vectors = result.unwrap();
        // First vector has invalid hex seed, gets skipped
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].tc_id, 2);
    }

    #[test]
    fn test_parse_vector_content_all_invalid_vectors_produces_empty() {
        let (_tmp, dl) = make_downloader();
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-768",
            vec![
                json!({
                    "tcId": 1,
                    "testCase": { "seed": "ZZZZ" },
                    "results": { "pk": "ccdd", "sk": "eeff" }
                }),
                json!({
                    "tcId": 2,
                    "testCase": {},
                    "results": { "pk": "ccdd", "sk": "eeff" }
                }),
            ],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_vector_content_invalid_utf8() {
        let (_tmp, dl) = make_downloader();
        let invalid = vec![0xFF, 0xFE, 0x00, 0x01];

        let result = dl.parse_vector_content(&invalid, "test");
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert!(e.to_string().contains("Invalid UTF-8"));
    }

    #[test]
    fn test_parse_vector_content_invalid_json() {
        let (_tmp, dl) = make_downloader();

        let result = dl.parse_vector_content(b"{ not valid json }", "test");
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert!(e.to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_parse_vector_content_empty_test_groups() {
        let (_tmp, dl) = make_downloader();
        let coll = make_collection_json("ML-KEM", vec![]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_vector_content_empty_tests_in_group() {
        let (_tmp, dl) = make_downloader();
        let group = make_group_json(1, "keyGen", "ML-KEM-768", vec![]);
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_vector_content_multiple_groups() {
        let (_tmp, dl) = make_downloader();
        let g1 = make_group_json(
            1,
            "keyGen",
            "ML-KEM-512",
            vec![json!({
                "tcId": 1,
                "testCase": { "seed": "aabb" },
                "results": { "pk": "ccdd", "sk": "eeff" }
            })],
        );
        let g2 = make_group_json(
            2,
            "keyGen",
            "ML-KEM-768",
            vec![json!({
                "tcId": 1,
                "testCase": { "seed": "1122" },
                "results": { "pk": "3344", "sk": "5566" }
            })],
        );
        let coll = make_collection_json("ML-KEM", vec![g1, g2]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].parameter_set, "ML-KEM-512");
        assert_eq!(vectors[1].parameter_set, "ML-KEM-768");
    }

    #[test]
    fn test_parse_vector_content_siggen() {
        let (_tmp, dl) = make_downloader();
        let group = make_group_json(
            1,
            "sigGen",
            "ML-DSA-65",
            vec![json!({
                "tcId": 1,
                "testCase": { "sk": "aabb", "message": "ccdd" },
                "results": { "signature": "eeff" }
            })],
        );
        let coll = make_collection_json("ML-DSA", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-DSA-sigGen");
        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].test_type, "sigGen");
    }

    #[test]
    fn test_parse_vector_content_sigver() {
        let (_tmp, dl) = make_downloader();
        let group = make_group_json(
            1,
            "sigVer",
            "ML-DSA-44",
            vec![json!({
                "tcId": 1,
                "testCase": { "pk": "aabb", "message": "ccdd" },
                "results": { "signature": "eeff", "test_passed": true }
            })],
        );
        let coll = make_collection_json("ML-DSA", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-DSA-sigVer");
        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].outputs.test_passed, Some(true));
    }

    #[test]
    fn test_parse_vector_content_with_invalid_parameter_set_skips() {
        let (_tmp, dl) = make_downloader();
        // Valid hex but invalid parameter set - vector will fail validation
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-999",
            vec![json!({
                "tcId": 1,
                "testCase": { "seed": "aabb" },
                "results": { "pk": "ccdd", "sk": "eeff" }
            })],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_ok());
        // Vector should be skipped because it has invalid parameter set
        assert!(result.unwrap().is_empty());
    }

    // ========================================================================
    // load_vectors_from_file
    // ========================================================================

    #[test]
    fn test_load_vectors_from_file_valid() {
        let (tmp, dl) = make_downloader();
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-768",
            vec![json!({
                "tcId": 1,
                "testCase": { "seed": "aabb" },
                "results": { "pk": "ccdd", "sk": "eeff" }
            })],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let file_path = tmp.path().join("ML-KEM-keyGen.json");
        fs::write(&file_path, serde_json::to_vec(&coll).unwrap()).unwrap();

        let result = dl.load_vectors_from_file(&file_path);
        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 1);
    }

    #[test]
    fn test_load_vectors_from_file_nonexistent() {
        let (tmp, dl) = make_downloader();
        let path = tmp.path().join("nonexistent.json");

        let result = dl.load_vectors_from_file(&path);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert!(e.to_string().contains("Failed to read"));
    }

    #[test]
    fn test_load_vectors_from_file_uses_file_stem_as_vector_type() {
        let (tmp, dl) = make_downloader();
        let coll = make_collection_json("ML-KEM", vec![]);
        let file_path = tmp.path().join("my-custom-name.json");
        fs::write(&file_path, serde_json::to_vec(&coll).unwrap()).unwrap();

        // Should succeed - file stem "my-custom-name" is used as vector_type
        let result = dl.load_vectors_from_file(&file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_vectors_from_file_without_extension() {
        let (tmp, dl) = make_downloader();
        let coll = make_collection_json("ML-KEM", vec![]);
        let file_path = tmp.path().join("no_extension");
        fs::write(&file_path, serde_json::to_vec(&coll).unwrap()).unwrap();

        let result = dl.load_vectors_from_file(&file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_vectors_from_file_corrupted_content() {
        let (tmp, dl) = make_downloader();
        let file_path = tmp.path().join("corrupted.json");
        fs::write(&file_path, "not valid json at all").unwrap();

        let result = dl.load_vectors_from_file(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_vectors_from_file_binary_content() {
        let (tmp, dl) = make_downloader();
        let file_path = tmp.path().join("binary.json");
        fs::write(&file_path, [0xFF, 0xFE, 0xFD]).unwrap();

        let result = dl.load_vectors_from_file(&file_path);
        assert!(result.is_err());
    }

    // ========================================================================
    // CavpVectorDownloader::new
    // ========================================================================

    #[test]
    fn test_downloader_new_creates_cache_dir() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        assert!(!nested.exists());

        let dl = CavpVectorDownloader::new(&nested);
        assert!(dl.is_ok());
        assert!(nested.exists());
    }

    #[test]
    fn test_downloader_new_existing_dir() {
        let tmp = TempDir::new().unwrap();
        // Creating with an already-existing directory should succeed
        let dl = CavpVectorDownloader::new(tmp.path());
        assert!(dl.is_ok());
    }

    // ========================================================================
    // Struct construction and serde round-trip
    // ========================================================================

    #[test]
    fn test_cavp_test_inputs_serde_roundtrip() {
        let inputs = CavpTestInputs {
            seed: Some("aabb".to_string()),
            pk: Some("ccdd".to_string()),
            sk: Some("eeff".to_string()),
            message: Some("0011".to_string()),
            ct: Some("2233".to_string()),
            ek: Some("4455".to_string()),
            dk: Some("6677".to_string()),
            m: Some("8899".to_string()),
            additional: HashMap::from([("custom".to_string(), serde_json::Value::Bool(true))]),
        };
        let json = serde_json::to_string(&inputs).unwrap();
        let deserialized: CavpTestInputs = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.seed, inputs.seed);
        assert_eq!(deserialized.pk, inputs.pk);
        assert_eq!(deserialized.sk, inputs.sk);
        assert_eq!(deserialized.message, inputs.message);
        assert_eq!(deserialized.ct, inputs.ct);
        assert_eq!(deserialized.ek, inputs.ek);
        assert_eq!(deserialized.dk, inputs.dk);
        assert_eq!(deserialized.m, inputs.m);
        assert!(deserialized.additional.contains_key("custom"));
    }

    #[test]
    fn test_cavp_test_outputs_serde_roundtrip() {
        let outputs = CavpTestOutputs {
            pk: Some("aabb".to_string()),
            sk: Some("ccdd".to_string()),
            signature: Some("eeff".to_string()),
            ct: Some("1122".to_string()),
            ss: Some("3344".to_string()),
            test_passed: Some(false),
            additional: HashMap::from([(
                "extra".to_string(),
                serde_json::Value::Number(42.into()),
            )]),
        };
        let json = serde_json::to_string(&outputs).unwrap();
        let deserialized: CavpTestOutputs = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pk, outputs.pk);
        assert_eq!(deserialized.sk, outputs.sk);
        assert_eq!(deserialized.signature, outputs.signature);
        assert_eq!(deserialized.ct, outputs.ct);
        assert_eq!(deserialized.ss, outputs.ss);
        assert_eq!(deserialized.test_passed, Some(false));
    }

    #[test]
    fn test_cavp_test_collection_serde_roundtrip() {
        let collection = CavpTestCollection {
            vs_id: 999,
            algorithm: "SLH-DSA".to_string(),
            revision: "3.0".to_string(),
            is_sample: false,
            test_groups: vec![CavpTestGroup {
                tg_id: 5,
                test_type: "sigGen".to_string(),
                parameter_set: "SLH-DSA-SHAKE-256f".to_string(),
                tests: vec![json!({"tcId": 1})],
            }],
        };
        let json = serde_json::to_string(&collection).unwrap();
        let deserialized: CavpTestCollection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.vs_id, 999);
        assert_eq!(deserialized.algorithm, "SLH-DSA");
        assert_eq!(deserialized.revision, "3.0");
        assert!(!deserialized.is_sample);
        assert_eq!(deserialized.test_groups.len(), 1);
        assert_eq!(deserialized.test_groups[0].parameter_set, "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn test_official_cavp_vector_serde_roundtrip() {
        let v = make_vector(
            "FN-DSA",
            "sigGen",
            "Falcon-512",
            CavpTestInputs {
                sk: Some("aabb".to_string()),
                message: Some("ccdd".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { signature: Some("eeff".to_string()), ..make_default_outputs() },
        );
        let json = serde_json::to_string(&v).unwrap();
        let deserialized: OfficialCavpVector = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.algorithm, "FN-DSA");
        assert_eq!(deserialized.parameter_set, "Falcon-512");
        assert_eq!(deserialized.inputs.sk, Some("aabb".to_string()));
        assert_eq!(deserialized.outputs.signature, Some("eeff".to_string()));
    }

    #[test]
    fn test_official_cavp_vector_clone() {
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-1024",
            CavpTestInputs { seed: Some("aabb".to_string()), ..make_default_inputs() },
            CavpTestOutputs {
                pk: Some("ccdd".to_string()),
                sk: Some("eeff".to_string()),
                ..make_default_outputs()
            },
        );
        let cloned = v.clone();
        assert_eq!(v.algorithm, cloned.algorithm);
        assert_eq!(v.inputs.seed, cloned.inputs.seed);
        assert_eq!(v.outputs.pk, cloned.outputs.pk);
    }

    #[test]
    fn test_official_cavp_vector_debug() {
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-512",
            make_default_inputs(),
            make_default_outputs(),
        );
        let debug_str = format!("{:?}", v);
        assert!(debug_str.contains("OfficialCavpVector"));
        assert!(debug_str.contains("ML-KEM"));
    }

    #[test]
    fn test_vector_validation_result_debug() {
        let r = VectorValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec!["test warning".to_string()],
            vector_id: "TEST-1-1".to_string(),
        };
        let debug_str = format!("{:?}", r);
        assert!(debug_str.contains("VectorValidationResult"));
        assert!(debug_str.contains("test warning"));
    }

    #[test]
    fn test_vector_validation_result_clone() {
        let r = VectorValidationResult {
            is_valid: false,
            errors: vec!["error1".to_string()],
            warnings: vec!["warn1".to_string()],
            vector_id: "ID-1-2".to_string(),
        };
        let cloned = r.clone();
        assert_eq!(r.is_valid, cloned.is_valid);
        assert_eq!(r.errors, cloned.errors);
        assert_eq!(r.warnings, cloned.warnings);
        assert_eq!(r.vector_id, cloned.vector_id);
    }

    // ========================================================================
    // Algorithm-specific validation coverage
    // ========================================================================

    #[test]
    fn test_validate_slhdsa_keygen() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "SLH-DSA",
            "keyGen",
            "SLH-DSA-SHA2-256f",
            CavpTestInputs { seed: Some("aabbccdd".to_string()), ..make_default_inputs() },
            CavpTestOutputs {
                pk: Some("11223344".to_string()),
                sk: Some("55667788".to_string()),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(r.is_valid);
    }

    #[test]
    fn test_validate_fndsa_siggen() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "FN-DSA",
            "sigGen",
            "Falcon-1024",
            CavpTestInputs {
                sk: Some("aabb".to_string()),
                message: Some("ccdd".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs { signature: Some("eeff".to_string()), ..make_default_outputs() },
        );
        let r = dl.validate_vector(&v);
        assert!(r.is_valid);
    }

    #[test]
    fn test_validate_fndsa_sigver() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "FN-DSA",
            "sigVer",
            "Falcon-512",
            CavpTestInputs {
                pk: Some("aabb".to_string()),
                message: Some("ccdd".to_string()),
                ..make_default_inputs()
            },
            CavpTestOutputs {
                signature: Some("eeff".to_string()),
                test_passed: Some(true),
                ..make_default_outputs()
            },
        );
        let r = dl.validate_vector(&v);
        assert!(r.is_valid);
    }

    // ========================================================================
    // parse_vector_content - convert_test_case error propagation
    // ========================================================================

    #[test]
    fn test_parse_vector_content_convert_error_propagates() {
        let (_tmp, dl) = make_downloader();
        // "testCase" is null => from_value(Null) fails => error propagated
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-768",
            vec![json!({
                "tcId": 1,
                "testCase": null,
                "results": { "pk": "aabb", "sk": "ccdd" }
            })],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vector_content_with_testcase_string_errors() {
        let (_tmp, dl) = make_downloader();
        // "testCase" is a string, not an object
        let group = make_group_json(
            1,
            "keyGen",
            "ML-KEM-768",
            vec![json!({
                "tcId": 1,
                "testCase": "invalid",
                "results": { "pk": "aabb", "sk": "ccdd" }
            })],
        );
        let coll = make_collection_json("ML-KEM", vec![group]);
        let content = serde_json::to_vec(&coll).unwrap();

        let result = dl.parse_vector_content(&content, "ML-KEM-keyGen");
        assert!(result.is_err());
    }

    // ========================================================================
    // Constants verification
    // ========================================================================

    #[test]
    fn test_constants() {
        assert!(NIST_CAVP_BASE_URL.contains("github"));
        assert!(NIST_CAVP_BASE_URL.contains("ACVP"));
        assert_eq!(MAX_CAVP_FILE_SIZE, 50 * 1024 * 1024);
        assert_eq!(HTTP_TIMEOUT, Duration::from_secs(30));
    }

    // ========================================================================
    // CavpTestGroup - direct struct tests
    // ========================================================================

    #[test]
    fn test_cavp_test_group_clone_and_debug() {
        let group = CavpTestGroup {
            tg_id: 7,
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-87".to_string(),
            tests: vec![json!({"tcId": 1}), json!({"tcId": 2})],
        };
        let cloned = group.clone();
        assert_eq!(group.tg_id, cloned.tg_id);
        assert_eq!(group.test_type, cloned.test_type);
        assert_eq!(group.tests.len(), cloned.tests.len());

        let debug = format!("{:?}", group);
        assert!(debug.contains("CavpTestGroup"));
        assert!(debug.contains("sigVer"));
    }

    // ========================================================================
    // Multiple validation errors at once
    // ========================================================================

    #[test]
    fn test_validate_keygen_all_fields_missing() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-KEM",
            "keyGen",
            "ML-KEM-768",
            make_default_inputs(),
            make_default_outputs(),
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        // Should have errors for missing seed, missing pk, missing sk
        assert!(r.errors.len() >= 3);
        assert!(r.errors.iter().any(|e| e.contains("Missing seed")));
        assert!(r.errors.iter().any(|e| e.contains("Missing expected public key")));
        assert!(r.errors.iter().any(|e| e.contains("Missing expected secret key")));
    }

    #[test]
    fn test_validate_siggen_all_fields_missing() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigGen",
            "ML-DSA-65",
            make_default_inputs(),
            make_default_outputs(),
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        assert!(r.errors.len() >= 3);
    }

    #[test]
    fn test_validate_sigver_all_fields_missing() {
        let (_tmp, dl) = make_downloader();
        let v = make_vector(
            "ML-DSA",
            "sigVer",
            "ML-DSA-44",
            make_default_inputs(),
            make_default_outputs(),
        );
        let r = dl.validate_vector(&v);
        assert!(!r.is_valid);
        // Should have errors for missing pk, missing message, missing signature
        assert!(r.errors.iter().any(|e| e.contains("Missing public key")));
        assert!(r.errors.iter().any(|e| e.contains("Missing message")));
        assert!(r.errors.iter().any(|e| e.contains("Missing signature for verification")));
        // And a warning for missing test_passed
        assert!(r.warnings.iter().any(|w| w.contains("Missing verification result")));
    }
}
