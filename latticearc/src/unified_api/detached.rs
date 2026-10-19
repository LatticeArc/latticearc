//! Versioned detached signatures with caller-pinned keys, algorithms and domains.
//!
//! V1 signs `b"LatticeArc-Detached-Signature\0" || 0x01 || algorithm_id ||
//! u16_be(domain.len()) || domain || u64_be(claims.len()) || claims`.
//! IDs: 1 = Ed25519, 2 = ML-DSA-44, 3 = ML-DSA-65, 4 = ML-DSA-87.
//! ML-DSA uses the pure FIPS 204 mode with an empty native context. Ed25519
//! uses ordinary Ed25519. Neither format uses an external prehash.
//!
//! Domains are 1–255 printable ASCII bytes (`0x21..=0x7e`). Claims are opaque
//! bytes; JSON whitespace, field order and Unicode normalization are significant.
//! The strict JSON record contains version, algorithm, domain and a canonical
//! padded standard-Base64 signature. It contains neither claims nor a public key.
//! Typed caller-supplied keys determine the algorithm; wire metadata cannot select
//! or downgrade it. ML-DSA-65 is the default for key generation. Ed25519 is an
//! explicit compatibility option in non-FIPS builds.
//!
//! # Example
//!
//! ```no_run
//! use latticearc::{CryptoConfig, generate_detached_keypair,
//!     sign_detached, verify_detached_with_key};
//! # fn example() -> Result<(), latticearc::unified_api::CoreError> {
//! let (public_key, secret_key) = generate_detached_keypair(CryptoConfig::new())?;
//! let claims = br#"{"sub":"alice"}"#;
//! let domain = "example.com/access-token";
//! let signed = sign_detached(
//!     claims, &secret_key, domain, CryptoConfig::new(),
//! )?;
//! let valid = verify_detached_with_key(
//!     claims, &signed, &public_key,
//!     domain, CryptoConfig::new(),
//! )?;
//! # if !valid { return Err(latticearc::unified_api::CoreError::VerificationFailed); }
//! # Ok(())
//! # }
//! ```

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::convenience::api::fips_verify_operational;
use super::{AlgorithmSelection, CoreError, CryptoConfig, Result, SecurityLevel};
#[cfg(not(feature = "fips"))]
use super::{SecurityMode, sign_ed25519, verify_ed25519};
use crate::primitives::resource_limits::validate_signature_size;
use crate::primitives::sig::ml_dsa::{
    self, MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};

const PREFIX: &[u8] = b"LatticeArc-Detached-Signature\0";
const VERSION: u8 = 1;
const MAX_RECORD_BYTES: usize = 8192;

/// Typed borrowed signing key. Its type fixes the algorithm, without wire metadata.
#[non_exhaustive]
pub enum DetachedSigningKey<'a> {
    /// Pure ML-DSA, with the parameter set carried by the key.
    MlDsa(&'a MlDsaSecretKey),
    /// Explicit classical compatibility: exactly a 32-byte Ed25519 secret seed.
    #[cfg(not(feature = "fips"))]
    Ed25519(&'a [u8]),
}

/// Caller-pinned borrowed verification key. Never obtain this from untrusted claims.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DetachedVerificationKey<'a> {
    /// Pure ML-DSA, with the parameter set pinned by the key's type.
    MlDsa(&'a MlDsaPublicKey),
    /// Explicit classical compatibility: exactly a 32-byte Ed25519 public key.
    #[cfg(not(feature = "fips"))]
    Ed25519(&'a [u8]),
}

impl<'a> From<&'a MlDsaSecretKey> for DetachedSigningKey<'a> {
    fn from(key: &'a MlDsaSecretKey) -> Self {
        Self::MlDsa(key)
    }
}

impl<'a> From<&'a MlDsaPublicKey> for DetachedVerificationKey<'a> {
    fn from(key: &'a MlDsaPublicKey) -> Self {
        Self::MlDsa(key)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    MlDsa(MlDsaParameterSet),
    #[cfg(not(feature = "fips"))]
    Ed25519,
}

impl Algorithm {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "ml-dsa-44" => Some(Self::MlDsa(MlDsaParameterSet::MlDsa44)),
            "ml-dsa-65" => Some(Self::MlDsa(MlDsaParameterSet::MlDsa65)),
            "ml-dsa-87" => Some(Self::MlDsa(MlDsaParameterSet::MlDsa87)),
            #[cfg(not(feature = "fips"))]
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::MlDsa(MlDsaParameterSet::MlDsa44) => "ml-dsa-44",
            Self::MlDsa(MlDsaParameterSet::MlDsa65) => "ml-dsa-65",
            Self::MlDsa(MlDsaParameterSet::MlDsa87) => "ml-dsa-87",
            #[cfg(not(feature = "fips"))]
            Self::Ed25519 => "ed25519",
        }
    }

    fn id(self) -> u8 {
        match self {
            Self::MlDsa(MlDsaParameterSet::MlDsa44) => 2,
            Self::MlDsa(MlDsaParameterSet::MlDsa65) => 3,
            Self::MlDsa(MlDsaParameterSet::MlDsa87) => 4,
            #[cfg(not(feature = "fips"))]
            Self::Ed25519 => 1,
        }
    }

    fn signature_size(self) -> usize {
        match self {
            Self::MlDsa(parameters) => parameters.signature_size(),
            #[cfg(not(feature = "fips"))]
            Self::Ed25519 => 64,
        }
    }
}

/// A detached v1 signature record. The verification key is never supplied by it.
///
/// Use [`Self::from_json`] for untrusted wire data. Verification revalidates all
/// fields even for records constructed or deserialized directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    /// Format version. Only `1` is accepted.
    pub version: u8,
    /// Exact algorithm name: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, or `ed25519`.
    /// Ed25519 is rejected in FIPS builds.
    pub algorithm: String,
    /// Application domain, also pinned independently at verification.
    pub domain: String,
    /// Canonical padded standard Base64 of the algorithm's exact signature size.
    pub signature: String,
}

impl DetachedSignature {
    /// Parse a bounded JSON record, rejecting duplicate/unknown fields and
    /// unsupported versions, algorithms, domains, or signature encodings.
    ///
    /// # Errors
    /// Returns [`CoreError::InvalidInput`] for an invalid record.
    pub fn from_json(json: &str) -> Result<Self> {
        if json.len() > MAX_RECORD_BYTES {
            return Err(invalid_record());
        }
        let record: Self = serde_json::from_str(json).map_err(|_error| invalid_record())?;
        record.signature_bytes()?;
        Ok(record)
    }

    /// Serialize a validated record. JSON field ordering is not signed.
    ///
    /// # Errors
    /// Returns an error if the record is invalid or serialization fails.
    pub fn to_json(&self) -> Result<String> {
        self.signature_bytes()?;
        serde_json::to_string(self).map_err(|_error| invalid_record())
    }

    fn signature_bytes(&self) -> Result<Vec<u8>> {
        let algorithm = Algorithm::from_name(&self.algorithm).ok_or_else(invalid_record)?;
        let size = algorithm.signature_size();
        let encoded_size = size.div_ceil(3).checked_mul(4).ok_or_else(invalid_record)?;
        if self.version != VERSION || self.signature.len() != encoded_size {
            return Err(invalid_record());
        }
        validate_domain(&self.domain)?;
        let bytes = STANDARD.decode(&self.signature).map_err(|_error| invalid_record())?;
        if bytes.len() != size || STANDARD.encode(&bytes) != self.signature {
            return Err(invalid_record());
        }
        Ok(bytes)
    }
}

fn invalid_record() -> CoreError {
    CoreError::InvalidInput("invalid detached signature record".to_owned())
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty()
        || domain.len() > 255
        || !domain.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(invalid_record());
    }
    Ok(())
}

fn validate_config(config: &CryptoConfig, algorithm: Algorithm) -> Result<()> {
    config.validate()?;
    if config.max_age_seconds().is_some() {
        return Err(CoreError::ConfigurationError(
            "detached records have no timestamp; enforce expiry in authenticated claims".into(),
        ));
    }
    if !matches!(config.get_selection(), AlgorithmSelection::SecurityLevel(_)) {
        return Err(CoreError::ConfigurationError(
            "detached signatures use typed keys; configure security level instead of use case or forced scheme".into()));
    }
    // FIPS-requiring compliance modes never reach this point in non-FIPS builds:
    // `config.validate()` rejects them, and FIPS builds have no Ed25519 variant.
    #[cfg(not(feature = "fips"))]
    if algorithm == Algorithm::Ed25519 && config.get_crypto_mode() == crate::CryptoMode::PqOnly {
        return Err(CoreError::ComplianceViolation(
            "Ed25519 is incompatible with the requested policy".into(),
        ));
    }
    config.validate_scheme_compliance(algorithm.name())
}

fn signing_input(claims: &[u8], domain: &str, algorithm: Algorithm) -> Result<Vec<u8>> {
    validate_domain(domain)?;
    let domain_len = u16::try_from(domain.len()).map_err(|_error| invalid_record())?;
    let claims_len = u64::try_from(claims.len()).map_err(|_error| invalid_record())?;
    let total = PREFIX
        .len()
        .checked_add(12)
        .and_then(|len| len.checked_add(domain.len()))
        .and_then(|len| len.checked_add(claims.len()))
        .ok_or_else(|| CoreError::ResourceExceeded("detached signature input too large".into()))?;
    validate_signature_size(total).map_err(|_error| {
        CoreError::ResourceExceeded("detached signature input too large".into())
    })?;
    let mut input = Vec::with_capacity(total);
    input.extend_from_slice(PREFIX);
    input.extend_from_slice(&[VERSION, algorithm.id()]);
    input.extend_from_slice(&domain_len.to_be_bytes());
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(&claims_len.to_be_bytes());
    input.extend_from_slice(claims);
    Ok(input)
}

/// Generate a pure post-quantum detached signing keypair.
///
/// `CryptoConfig::new()` chooses ML-DSA-65. Explicit Standard/High/Maximum levels
/// choose ML-DSA-44/65/87. The secret is automatically zeroized on drop.
///
/// # Errors
/// Returns an error for invalid policy/session, module failure or key generation failure.
pub fn generate_detached_keypair(config: CryptoConfig) -> Result<(MlDsaPublicKey, MlDsaSecretKey)> {
    fips_verify_operational()?;
    let parameters = match config.get_selection() {
        AlgorithmSelection::SecurityLevel(SecurityLevel::Standard) => MlDsaParameterSet::MlDsa44,
        AlgorithmSelection::SecurityLevel(SecurityLevel::High) => MlDsaParameterSet::MlDsa65,
        AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum) => MlDsaParameterSet::MlDsa87,
        _ => {
            return Err(CoreError::ConfigurationError(
                "detached key generation requires a security level".into(),
            ));
        }
    };
    validate_config(&config, Algorithm::MlDsa(parameters))?;
    ml_dsa::generate_keypair(parameters).map_err(|_error| CoreError::KeyGenerationFailed {
        reason: "detached ML-DSA key generation failed".into(),
        recovery: "retry with a working secure random source".into(),
    })
}

/// Sign exact claims bytes with a typed key, binding the version, algorithm and domain.
///
/// The key determines the algorithm; there is no classical fallback. Configuration
/// controls session, compliance and minimum security level, just as for encryption.
///
/// # Errors
/// Returns an error for invalid key/domain/policy, resource limit or operational failure.
#[must_use = "the detached signature or signing error must be handled"]
pub fn sign_detached<'a>(
    claims: &[u8],
    key: impl Into<DetachedSigningKey<'a>>,
    domain: &str,
    config: CryptoConfig,
) -> Result<DetachedSignature> {
    fips_verify_operational()?;
    let key = key.into();
    let algorithm = match key {
        DetachedSigningKey::MlDsa(sk) => Algorithm::MlDsa(sk.parameter_set()),
        #[cfg(not(feature = "fips"))]
        DetachedSigningKey::Ed25519(_) => Algorithm::Ed25519,
    };
    validate_config(&config, algorithm)?;
    let input = signing_input(claims, domain, algorithm)?;
    let signature = match key {
        DetachedSigningKey::MlDsa(sk) => sk
            .sign(&input, b"")
            .map_err(|_error| CoreError::SignatureFailed("detached ML-DSA signing failed".into()))?
            .to_bytes(),
        #[cfg(not(feature = "fips"))]
        DetachedSigningKey::Ed25519(seed) => sign_ed25519(&input, seed, SecurityMode::Unverified)?,
    };
    Ok(DetachedSignature {
        version: VERSION,
        algorithm: algorithm.name().to_owned(),
        domain: domain.to_owned(),
        signature: STANDARD.encode(signature),
    })
}

/// Verify exact claims bytes with a typed caller-pinned key and expected domain.
///
/// Algorithm mismatches, malformed records and invalid signatures return `Ok(false)`.
/// There is no format auto-detection or downgrade. The key must come from trusted
/// configuration; claim semantics, expiry, authorization and replay are caller policy.
///
/// # Errors
/// Returns an error for invalid caller key/domain/policy, resource limit or operational failure.
#[must_use = "verification must succeed before trusting claims"]
pub fn verify_detached_with_key<'a>(
    claims: &[u8],
    signature: &DetachedSignature,
    key: impl Into<DetachedVerificationKey<'a>>,
    expected_domain: &str,
    config: CryptoConfig,
) -> Result<bool> {
    fips_verify_operational()?;
    let key = key.into();
    let algorithm = match key {
        DetachedVerificationKey::MlDsa(pk) => Algorithm::MlDsa(pk.parameter_set()),
        #[cfg(not(feature = "fips"))]
        DetachedVerificationKey::Ed25519(pk) => {
            if pk.len() != 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: pk.len() });
            }
            Algorithm::Ed25519
        }
    };
    validate_config(&config, algorithm)?;
    validate_domain(expected_domain)?;
    if signature.algorithm != algorithm.name() || signature.domain != expected_domain {
        return Ok(false);
    }
    let Ok(bytes) = signature.signature_bytes() else {
        return Ok(false);
    };
    let input = signing_input(claims, expected_domain, algorithm)?;
    match key {
        DetachedVerificationKey::MlDsa(pk) => {
            let Ok(parsed) = MlDsaSignature::new(pk.parameter_set(), bytes) else {
                return Ok(false);
            };
            Ok(pk.verify(&input, &parsed, b"").unwrap_or(false))
        }
        #[cfg(not(feature = "fips"))]
        DetachedVerificationKey::Ed25519(pk) => {
            verify_ed25519(&input, &bytes, pk, SecurityMode::Unverified)
        }
    }
}
