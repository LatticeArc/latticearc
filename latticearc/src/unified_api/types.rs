#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Core type definitions for LatticeArc cryptographic operations.
//!
//! This module provides fundamental types used throughout the LatticeArc library,
//! including security-sensitive types like [`ZeroizedBytes`], payload types like
//! [`CryptoPayload`], and configuration types like [`SecurityLevel`] and [`CryptoScheme`].

use subtle::Choice;
use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::unified_api::error::VerificationError;

/// Bytes that are automatically zeroized when dropped.
///
/// This type is used for sensitive data (keys, secrets) to ensure
/// they are securely erased from memory when no longer needed.
///
/// # Examples
///
/// ```rust
/// use latticearc::unified_api::types::ZeroizedBytes;
///
/// {
///     let sensitive = ZeroizedBytes::new(vec![0u8; 32]);
///     // Use sensitive data...
/// } // ZeroizedBytes is dropped and data is zeroized
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct ZeroizedBytes {
    data: Vec<u8>,
}

impl ZeroizedBytes {
    /// Create new zeroized bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to wrap
    ///
    /// # Returns
    ///
    /// A new ZeroizedBytes instance
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get data as a slice.
    ///
    /// # Returns
    ///
    /// A reference to the underlying data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Convert to a `Vec<u8>` (clone).
    ///
    /// # Returns
    ///
    /// A clone of the underlying data
    pub fn into_vec(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Get length of data.
    ///
    /// # Returns
    ///
    /// The length in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if data is empty.
    ///
    /// # Returns
    ///
    /// `true` if data is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Parse from hex string (requires `serde` feature).
    #[cfg(feature = "serde")]
    pub fn from_hex(hex: &str) -> Result<Self, crate::unified_api::error::CryptoError> {
        hex::decode(hex).map(ZeroizedBytes::new).map_err(|e| {
            crate::unified_api::error::CryptoError::InvalidInput(format!("Invalid hex: {}", e))
        })
    }

    /// Convert to hex string (requires `serde` feature).
    #[cfg(feature = "serde")]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.data)
    }

    /// Parse from base64 string (requires `serde` feature).
    #[cfg(feature = "serde")]
    pub fn from_base64(b64: &str) -> Result<Self, crate::unified_api::error::CryptoError> {
        base64::decode(b64).map(ZeroizedBytes::new).map_err(|e| {
            crate::unified_api::error::CryptoError::InvalidInput(format!("Invalid base64: {}", e))
        })
    }

    /// Convert to base64 string (requires `serde` feature).
    #[cfg(feature = "serde")]
    pub fn to_base64(&self) -> String {
        base64::encode(&self.data)
    }
}

impl AsRef<[u8]> for ZeroizedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for ZeroizedBytes {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// A generic crypto payload with metadata.
///
/// This type wraps encrypted or signed data with associated metadata.
///
/// # Type Parameters
///
/// * `T` - The metadata type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct CryptoPayload<T> {
    /// The payload data
    pub data: Vec<u8>,
    /// Associated metadata
    pub metadata: T,
    /// The cryptographic scheme used
    pub scheme: CryptoScheme,
    /// Unix timestamp in seconds
    pub timestamp: u64,
}

impl<T> CryptoPayload<T> {
    /// Get length of payload data.
    ///
    /// # Returns
    ///
    /// The length in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if payload data is empty.
    ///
    /// # Returns
    ///
    /// `true` if data is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Metadata for encrypted data.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct EncryptedMetadata {
    /// Nonce for AEAD encryption
    pub nonce: Vec<u8>,
    /// Authentication tag (if applicable)
    pub tag: Option<Vec<u8>>,
    /// Key identifier (optional)
    pub key_id: Option<String>,
}

/// Encrypted data with metadata.
///
/// This is an alias for [`CryptoPayload<EncryptedMetadata>`].
pub type EncryptedData = CryptoPayload<EncryptedMetadata>;

/// Metadata for signed data.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SignedMetadata {
    /// The signature
    pub signature: Vec<u8>,
    /// The signature algorithm used
    pub signature_algorithm: CryptoScheme,
    /// Key identifier (optional)
    pub key_id: Option<String>,
}

/// Signed data with metadata.
///
/// This is an alias for [`CryptoPayload<SignedMetadata>`].
pub type SignedData = CryptoPayload<SignedMetadata>;

/// Public key (alias for `Vec<u8>`).
pub type PublicKey = Vec<u8>;

/// Private key (alias for ZeroizedBytes).
pub type PrivateKey = ZeroizedBytes;

/// Symmetric key (alias for ZeroizedBytes).
pub type SymmetricKey = ZeroizedBytes;

/// Hash output (32 bytes, suitable for SHA3-256).
pub type HashOutput = [u8; 32];

/// Key pair (public key and private key).
pub type KeyPair = (PublicKey, PrivateKey);

/// Data characteristics for scheme selection.
///
/// This struct represents the analyzed properties of data for cryptographic scheme selection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataCharacteristics {
    /// Data size in bytes
    pub size: usize,
    /// Data entropy (0-8, where 8 is maximum randomness)
    pub entropy: f64,
    /// Data compressibility (0-1, where 1 is highly compressible)
    pub compressibility: f64,
    /// Data structure
    pub structure: DataStructure,
}

/// Data structure types.
///
/// This enum represents the detected structure of data for optimal scheme selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStructure {
    /// Unstructured data (no clear pattern)
    Unstructured,
    /// Structured data (JSON, XML, etc.)
    Structured,
    /// Numeric data (numbers)
    Numeric,
    /// Text data (strings, text documents)
    Text,
    /// Binary data (arbitrary bytes)
    Binary,
}

/// Hardware types supported by the system.
///
/// This enum represents different hardware acceleration options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HardwareType {
    /// CPU (always available)
    Cpu,
    /// GPU (if available)
    Gpu,
    /// FPGA (if available)
    Fpga,
    /// TPU (if available)
    Tpu,
    /// Intel SGX enclave (if available)
    Sgx,
}

impl std::fmt::Display for HardwareType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardwareType::Cpu => write!(f, "CPU"),
            HardwareType::Gpu => write!(f, "GPU"),
            HardwareType::Fpga => write!(f, "FPGA"),
            HardwareType::Tpu => write!(f, "TPU"),
            HardwareType::Sgx => write!(f, "SGX"),
        }
    }
}

/// Information about available hardware.
///
/// This struct represents detected hardware capabilities.
#[derive(Debug, Clone)]
pub struct HardwareInfo {
    /// FPGA availability
    pub has_fpga: bool,
    /// TPU availability
    pub has_tpu: bool,
    /// GPU availability
    pub has_gpu: bool,
    /// Intel SGX availability
    pub has_sgx: bool,
    /// CPU features
    pub cpu_features: crate::unified_api::hardware::CpuFeatures,
    /// Recommended accelerator (if any)
    pub recommended_accelerator: Option<HardwareType>,
}

/// Context for cryptographic operations.
///
/// This struct provides context for cryptographic operations, including
/// security level, performance preferences, hardware preferences, and custom parameters.
///
/// # Examples
///
/// ```rust
/// use latticearc::unified_api::types::*;
/// use latticearc::unified_api::config::*;
///
/// let ctx = CryptoContext {
///     security_level: SecurityLevel::High,
///     performance_preference: PerformancePreference::Balanced,
///     hardware_preference: HardwarePreference::Auto,
///     custom_params: None,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CryptoContext {
    /// Security level (Standard, High, Maximum, Custom)
    pub security_level: SecurityLevel,
    /// Performance preference (Speed, Throughput, Latency, Memory, Balanced)
    pub performance_preference: PerformancePreference,
    /// Hardware preference (Auto, CpuOnly, GpuPreferred, etc.)
    pub hardware_preference: HardwarePreference,
    /// Custom parameters (algorithm-specific)
    pub custom_params: Option<Vec<(String, Vec<u8>)>>,
}

impl Default for CryptoContext {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Standard,
            performance_preference: PerformancePreference::Balanced,
            hardware_preference: HardwarePreference::Auto,
            custom_params: None,
        }
    }
}

/// Security levels for cryptographic operations.
///
/// - `Standard` - 128-bit security (NIST Level 1)
/// - `High` - 192-bit security (NIST Level 3)
/// - `Maximum` - 256-bit security (NIST Level 5)
/// - `Custom { security_bits }` - Custom security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default)]
pub enum SecurityLevel {
    /// Standard security (128-bit)
    #[default]
    Standard,
    /// High security (192-bit)
    High,
    /// Maximum security (256-bit)
    Maximum,
    /// Custom security level
    Custom { security_bits: u32 },
}

impl SecurityLevel {
    /// Convert security level to security bits.
    ///
    /// # Returns
    ///
    /// The security level in bits
    pub fn as_bits(&self) -> u32 {
        match self {
            SecurityLevel::Standard => 128,
            SecurityLevel::High => 192,
            SecurityLevel::Maximum => 256,
            SecurityLevel::Custom { security_bits } => *security_bits,
        }
    }

    /// Convert from security bits to security level.
    ///
    /// # Arguments
    ///
    /// * `bits` - The security bits
    ///
    /// # Returns
    ///
    /// The corresponding security level
    pub fn from_bits(bits: u32) -> Self {
        match bits {
            0..=128 => SecurityLevel::Standard,
            129..=192 => SecurityLevel::High,
            193..=256 => SecurityLevel::Maximum,
            _ => SecurityLevel::Custom { security_bits: bits },
        }
    }
}

/// Performance preferences for cryptographic operations.
///
/// - `Speed` - Minimize latency (best for small data)
/// - `Throughput` - Maximize throughput (best for large data)
/// - `Latency` - Minimize latency (same as Speed)
/// - `Memory` - Minimize memory usage
/// - `Balanced` - Balance all factors (default)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformancePreference {
    /// Minimize latency
    Speed,
    /// Maximize throughput
    Throughput,
    /// Minimize latency (same as Speed)
    Latency,
    /// Minimize memory usage
    Memory,
    /// Balance all factors (default)
    Balanced,
}

/// Hardware preferences for cryptographic operations.
///
/// - `Auto` - Auto-detect and use best hardware (default)
/// - `CpuOnly` - CPU only (most compatible)
/// - `GpuPreferred` - Prefer GPU acceleration
/// - `FpgaPreferred` - Prefer FPGA acceleration
/// - `TpuPreferred` - Prefer TPU acceleration
/// - `SgxPreferred` - Prefer SGX enclaves
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwarePreference {
    /// Auto-detect and use best hardware
    Auto,
    /// CPU only
    CpuOnly,
    /// Prefer GPU acceleration
    GpuPreferred,
    /// Prefer FPGA acceleration
    FpgaPreferred,
    /// Prefer TPU acceleration
    TpuPreferred,
    /// Prefer SGX enclaves
    SgxPreferred,
}

/// Cryptographic scheme enumeration.
///
/// This enum represents all supported cryptographic schemes in LatticeArc.
///
/// # Variants
///
/// - `Homomorphic` - Homomorphic encryption schemes (Paillier, BFV, CKKS, TFHE)
/// - `MultiParty` - Multi-party computation schemes (FROST, SPDZ, Yao)
/// - `OrderRevealing` - Order-revealing encryption schemes
/// - `Searchable` - Searchable symmetric encryption schemes
/// - `HybridPq` - Hybrid post-quantum encryption (ML-KEM + AEAD)
/// - `Classical` - Classical cryptographic schemes (AES-GCM, ChaCha20-Poly1305, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoScheme {
    /// Homomorphic encryption
    Homomorphic(HomomorphicScheme),
    /// Multi-party computation
    MultiParty(MpcScheme),
    /// Order-revealing encryption
    OrderRevealing(OreScheme),
    /// Searchable encryption
    Searchable(SseScheme),
    /// Hybrid post-quantum encryption
    HybridPq,
    /// Classical cryptography
    Classical(ClassicalScheme),
}

impl Default for CryptoScheme {
    fn default() -> Self {
        CryptoScheme::Classical(ClassicalScheme::default())
    }
}

#[cfg(feature = "serde")]
impl Serialize for CryptoScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CryptoScheme::Homomorphic(scheme) => {
                serializer.serialize_str(&format!("Homomorphic:{}", scheme))
            }
            CryptoScheme::MultiParty(scheme) => {
                serializer.serialize_str(&format!("MultiParty:{}", scheme))
            }
            CryptoScheme::OrderRevealing(scheme) => {
                serializer.serialize_str(&format!("OrderRevealing:{}", scheme))
            }
            CryptoScheme::Searchable(scheme) => {
                serializer.serialize_str(&format!("Searchable:{}", scheme))
            }
            CryptoScheme::HybridPq => serializer.serialize_str("HybridPq"),
            CryptoScheme::Classical(scheme) => {
                serializer.serialize_str(&format!("Classical:{}", scheme))
            }
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for CryptoScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = CryptoScheme;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a crypto scheme string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let parts: Vec<&str> = v.split(':').collect();
                if parts.len() != 2 {
                    return Err(serde::de::Error::custom(format!(
                        "invalid crypto scheme format: {}",
                        v
                    )));
                }
                let (scheme_type, scheme_name) = (parts[0], parts[1]);
                match scheme_type {
                    "Homomorphic" => {
                        let scheme = match scheme_name {
                            "Paillier" => HomomorphicScheme::Paillier,
                            "BFV" => HomomorphicScheme::BFV,
                            "CKKS" => HomomorphicScheme::CKKS,
                            "TFHE" => HomomorphicScheme::TFHE,
                            _ => {
                                return Err(serde::de::Error::custom(format!(
                                    "unknown homomorphic scheme: {}",
                                    scheme_name
                                )));
                            }
                        };
                        Ok(CryptoScheme::Homomorphic(scheme))
                    }
                    "MultiParty" => {
                        let scheme = match scheme_name {
                            "FROST" => MpcScheme::FROST,
                            "SPDZ" => MpcScheme::SPDZ,
                            "Yao" => MpcScheme::Yao,
                            _ => {
                                return Err(serde::de::Error::custom(format!(
                                    "unknown MPC scheme: {}",
                                    scheme_name
                                )));
                            }
                        };
                        Ok(CryptoScheme::MultiParty(scheme))
                    }
                    "OrderRevealing" => {
                        let scheme = match scheme_name {
                            "Basic" => OreScheme::Basic,
                            "Optimized" => OreScheme::Optimized,
                            _ => {
                                return Err(serde::de::Error::custom(format!(
                                    "unknown ORE scheme: {}",
                                    scheme_name
                                )));
                            }
                        };
                        Ok(CryptoScheme::OrderRevealing(scheme))
                    }
                    "Searchable" => {
                        let scheme = match scheme_name {
                            "Deterministic" => SseScheme::Deterministic,
                            "Dynamic" => SseScheme::Dynamic,
                            "Verifiable" => SseScheme::Verifiable,
                            _ => {
                                return Err(serde::de::Error::custom(format!(
                                    "unknown SSE scheme: {}",
                                    scheme_name
                                )));
                            }
                        };
                        Ok(CryptoScheme::Searchable(scheme))
                    }
                    "HybridPq" => Ok(CryptoScheme::HybridPq),
                    "Classical" => {
                        let scheme = match scheme_name {
                            "Aes256Gcm" => ClassicalScheme::Aes256Gcm,
                            "ChaCha20Poly1305" => ClassicalScheme::ChaCha20Poly1305,
                            "X25519" => ClassicalScheme::X25519,
                            "Ed25519" => ClassicalScheme::Ed25519,
                            "P256" => ClassicalScheme::P256,
                            "Secp256k1" => ClassicalScheme::Secp256k1,
                            _ => {
                                return Err(serde::de::Error::custom(format!(
                                    "unknown classical scheme: {}",
                                    scheme_name
                                )));
                            }
                        };
                        Ok(CryptoScheme::Classical(scheme))
                    }
                    _ => Err(serde::de::Error::custom(format!(
                        "unknown crypto scheme type: {}",
                        scheme_type
                    ))),
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Homomorphic encryption schemes.
///
/// - `Paillier` - Paillier homomorphic encryption
/// - `BFV` - BFV homomorphic encryption
/// - `CKKS` - CKKS homomorphic encryption (for floating-point numbers)
/// - `TFHE` - TFHE (Fully Homomorphic Encryption over Torus)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HomomorphicScheme {
    /// Paillier homomorphic encryption
    #[default]
    Paillier,
    /// BFV homomorphic encryption
    BFV,
    /// CKKS homomorphic encryption (for floating-point numbers)
    CKKS,
    /// TFHE (Fully Homomorphic Encryption over Torus)
    TFHE,
}

impl std::fmt::Display for HomomorphicScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HomomorphicScheme::Paillier => write!(f, "Paillier"),
            HomomorphicScheme::BFV => write!(f, "BFV"),
            HomomorphicScheme::CKKS => write!(f, "CKKS"),
            HomomorphicScheme::TFHE => write!(f, "TFHE"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for HomomorphicScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            HomomorphicScheme::Paillier => serializer.serialize_str("Paillier"),
            HomomorphicScheme::BFV => serializer.serialize_str("BFV"),
            HomomorphicScheme::CKKS => serializer.serialize_str("CKKS"),
            HomomorphicScheme::TFHE => serializer.serialize_str("TFHE"),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for HomomorphicScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HomomorphicScheme;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a homomorphic scheme string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "Paillier" => Ok(HomomorphicScheme::Paillier),
                    "BFV" => Ok(HomomorphicScheme::BFV),
                    "CKKS" => Ok(HomomorphicScheme::CKKS),
                    "TFHE" => Ok(HomomorphicScheme::TFHE),
                    _ => {
                        Err(serde::de::Error::custom(format!("unknown homomorphic scheme: {}", v)))
                    }
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Multi-party computation schemes.
///
/// - `FROST` - Flexible Round-Optimized Schnorr Threshold signatures
/// - `SPDZ` - SPDZ protocol for MPC
/// - `Yao` - Yao's garbled circuits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MpcScheme {
    /// FROST threshold signatures
    #[default]
    FROST,
    /// SPDZ protocol
    SPDZ,
    /// Yao's garbled circuits
    Yao,
}

impl std::fmt::Display for MpcScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcScheme::FROST => write!(f, "FROST"),
            MpcScheme::SPDZ => write!(f, "SPDZ"),
            MpcScheme::Yao => write!(f, "Yao"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for MpcScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            MpcScheme::FROST => serializer.serialize_str("FROST"),
            MpcScheme::SPDZ => serializer.serialize_str("SPDZ"),
            MpcScheme::Yao => serializer.serialize_str("Yao"),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MpcScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = MpcScheme;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a MPC scheme string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "FROST" => Ok(MpcScheme::FROST),
                    "SPDZ" => Ok(MpcScheme::SPDZ),
                    "Yao" => Ok(MpcScheme::Yao),
                    _ => Err(serde::de::Error::custom(format!("unknown MPC scheme: {}", v))),
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Order-revealing encryption schemes.
///
/// - `Basic` - Basic order-revealing encryption
/// - `Optimized` - Optimized order-revealing encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OreScheme {
    /// Basic order-revealing encryption
    #[default]
    Basic,
    /// Optimized order-revealing encryption
    Optimized,
}

impl std::fmt::Display for OreScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OreScheme::Basic => write!(f, "Basic"),
            OreScheme::Optimized => write!(f, "Optimized"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for OreScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OreScheme::Basic => serializer.serialize_str("Basic"),
            OreScheme::Optimized => serializer.serialize_str("Optimized"),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for OreScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = OreScheme;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an ORE scheme string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "Basic" => Ok(OreScheme::Basic),
                    "Optimized" => Ok(OreScheme::Optimized),
                    _ => Err(serde::de::Error::custom(format!("unknown ORE scheme: {}", v))),
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Searchable symmetric encryption schemes.
///
/// - `Deterministic` - Deterministic SSE
/// - `Dynamic` - Dynamic SSE
/// - `Verifiable` - Verifiable SSE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SseScheme {
    /// Deterministic SSE
    #[default]
    Deterministic,
    /// Dynamic SSE
    Dynamic,
    /// Verifiable SSE
    Verifiable,
}

impl std::fmt::Display for SseScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SseScheme::Deterministic => write!(f, "Deterministic"),
            SseScheme::Dynamic => write!(f, "Dynamic"),
            SseScheme::Verifiable => write!(f, "Verifiable"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for SseScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SseScheme::Deterministic => serializer.serialize_str("Deterministic"),
            SseScheme::Dynamic => serializer.serialize_str("Dynamic"),
            SseScheme::Verifiable => serializer.serialize_str("Verifiable"),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SseScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SseScheme;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an SSE scheme string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "Deterministic" => Ok(SseScheme::Deterministic),
                    "Dynamic" => Ok(SseScheme::Dynamic),
                    "Verifiable" => Ok(SseScheme::Verifiable),
                    _ => Err(serde::de::Error::custom(format!("unknown SSE scheme: {}", v))),
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Classical cryptographic schemes.
///
/// - `Aes256Gcm` - AES-256-GCM AEAD
/// - `ChaCha20Poly1305` - ChaCha20-Poly1305 AEAD
/// - `X25519` - X25519 key exchange
/// - `Ed25519` - Ed25519 signatures
/// - `P256` - NIST P-256 EC
/// - `Secp256k1` - secp256k1 EC (Bitcoin)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClassicalScheme {
    /// AES-256-GCM AEAD
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305 AEAD
    ChaCha20Poly1305,
    /// X25519 key exchange
    X25519,
    /// Ed25519 signatures
    Ed25519,
    /// NIST P-256 EC
    P256,
    /// secp256k1 EC (Bitcoin)
    Secp256k1,
}

impl std::fmt::Display for ClassicalScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassicalScheme::Aes256Gcm => write!(f, "Aes256Gcm"),
            ClassicalScheme::ChaCha20Poly1305 => write!(f, "ChaCha20Poly1305"),
            ClassicalScheme::X25519 => write!(f, "X25519"),
            ClassicalScheme::Ed25519 => write!(f, "Ed25519"),
            ClassicalScheme::P256 => write!(f, "P256"),
            ClassicalScheme::Secp256k1 => write!(f, "Secp256k1"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for ClassicalScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ClassicalScheme::Aes256Gcm => serializer.serialize_str("Aes256Gcm"),
            ClassicalScheme::ChaCha20Poly1305 => serializer.serialize_str("ChaCha20Poly1305"),
            ClassicalScheme::X25519 => serializer.serialize_str("X25519"),
            ClassicalScheme::Ed25519 => serializer.serialize_str("Ed25519"),
            ClassicalScheme::P256 => serializer.serialize_str("P256"),
            ClassicalScheme::Secp256k1 => serializer.serialize_str("Secp256k1"),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ClassicalScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ClassicalScheme;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a classical scheme string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "Aes256Gcm" => Ok(ClassicalScheme::Aes256Gcm),
                    "ChaCha20Poly1305" => Ok(ClassicalScheme::ChaCha20Poly1305),
                    "X25519" => Ok(ClassicalScheme::X25519),
                    "Ed25519" => Ok(ClassicalScheme::Ed25519),
                    "P256" => Ok(ClassicalScheme::P256),
                    "Secp256k1" => Ok(ClassicalScheme::Secp256k1),
                    _ => Err(serde::de::Error::custom(format!("unknown classical scheme: {}", v))),
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Verification status with metadata.
///
/// This struct represents the result of a verification operation.
#[derive(Debug, Clone)]
pub struct VerificationStatus {
    /// Whether verification succeeded (constant-time)
    pub verified: Choice,
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Confidence score (0-1)
    pub confidence: f64,
}

impl VerificationStatus {
    /// Create new verification status.
    ///
    /// # Arguments
    ///
    /// * `verified` - Whether verification succeeded
    /// * `timestamp` - Unix timestamp in seconds
    ///
    /// # Returns
    ///
    /// A new VerificationStatus instance
    pub fn new(verified: bool, timestamp: u64) -> Self {
        Self {
            verified: Choice::from(verified as u8),
            timestamp,
            confidence: if verified { 1.0 } else { 0.0 },
        }
    }

    /// Check if verification succeeded.
    ///
    /// # Returns
    ///
    /// `true` if verification succeeded
    pub fn is_verified(&self) -> bool {
        self.verified.into()
    }

    /// Convert to Result.
    ///
    /// # Returns
    ///
    /// `Ok(())` if verified, `Err(VerificationError::AuthenticationFailed)` otherwise
    pub fn into_result(self) -> Result<(), VerificationError> {
        if self.is_verified() { Ok(()) } else { Err(VerificationError::AuthenticationFailed) }
    }
}

impl TryFrom<VerificationError> for VerificationStatus {
    type Error = VerificationError;

    fn try_from(err: VerificationError) -> Result<Self, Self::Error> {
        Err(err)
    }
}
