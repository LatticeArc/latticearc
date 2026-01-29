//! Core traits for cryptographic operations.
//!
//! Defines the interfaces for encryption, decryption, signing, verification,
//! key derivation, and hardware-aware operations.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::{error::Result, types::CryptoContext};
use async_trait::async_trait;

/// Trait for types that can encrypt data.
pub trait Encryptable {
    /// The output type of encryption operations.
    type Output;
    /// The error type for encryption failures.
    type Error;

    /// Encrypts data with default settings.
    ///
    /// # Errors
    /// Returns an error if encryption fails (implementation-defined).
    fn encrypt(&self, data: &[u8]) -> std::result::Result<Self::Output, Self::Error>;

    /// Encrypts data with the provided cryptographic context.
    ///
    /// # Errors
    /// Returns an error if encryption fails (implementation-defined).
    fn encrypt_with_context(
        &self,
        data: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<Self::Output, Self::Error>;
}

/// Trait for types that can decrypt data.
pub trait Decryptable {
    /// The output type of decryption operations.
    type Output;
    /// The error type for decryption failures.
    type Error;

    /// Decrypts data with default settings.
    ///
    /// # Errors
    /// Returns an error if decryption fails (implementation-defined).
    fn decrypt(&self, encrypted: &[u8]) -> std::result::Result<Self::Output, Self::Error>;

    /// Decrypts data with the provided cryptographic context.
    ///
    /// # Errors
    /// Returns an error if decryption fails (implementation-defined).
    fn decrypt_with_context(
        &self,
        encrypted: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<Self::Output, Self::Error>;
}

/// Trait for types that can sign messages.
pub trait Signable {
    /// The output type of signing operations (typically a signature).
    type Output;
    /// The error type for signing failures.
    type Error;

    /// Signs a message with default settings.
    ///
    /// # Errors
    /// Returns an error if signing fails (implementation-defined).
    fn sign(&self, message: &[u8]) -> std::result::Result<Self::Output, Self::Error>;

    /// Signs a message with the provided cryptographic context.
    ///
    /// # Errors
    /// Returns an error if signing fails (implementation-defined).
    fn sign_with_context(
        &self,
        message: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<Self::Output, Self::Error>;
}

/// Trait for types that can verify signatures.
pub trait Verifiable {
    /// The error type for verification failures.
    type Error;

    /// Verifies a signature against a message.
    ///
    /// # Errors
    /// Returns an error if verification fails (implementation-defined).
    fn verify(&self, message: &[u8], signature: &[u8]) -> std::result::Result<bool, Self::Error>;

    /// Verifies a signature with the provided cryptographic context.
    ///
    /// # Errors
    /// Returns an error if verification fails (implementation-defined).
    fn verify_with_context(
        &self,
        message: &[u8],
        signature: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<bool, Self::Error>;
}

/// Trait for types that can derive keys.
pub trait KeyDerivable {
    /// The output type of key derivation (typically a key).
    type Output;
    /// The error type for derivation failures.
    type Error;

    /// Derives a key from input material and application-specific info.
    ///
    /// # Errors
    /// Returns an error if key derivation fails (implementation-defined).
    fn derive_key(
        &self,
        input: &[u8],
        info: &[u8],
        length: usize,
    ) -> std::result::Result<Self::Output, Self::Error>;

    /// Derives a key from a password using a salt.
    ///
    /// # Errors
    /// Returns an error if key derivation fails (implementation-defined).
    fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        length: usize,
    ) -> std::result::Result<Self::Output, Self::Error>;
}

/// Async version of [`Encryptable`] for async cryptographic operations.
#[async_trait]
pub trait AsyncEncryptable: Send + Sync {
    /// The output type of encryption operations.
    type Output;
    /// The error type for encryption failures.
    type Error;

    /// Encrypts data asynchronously with default settings.
    ///
    /// # Errors
    /// Returns an error if encryption fails (implementation-defined).
    async fn encrypt(&self, data: &[u8]) -> Result<Self::Output>;

    /// Encrypts data asynchronously with the provided context.
    ///
    /// # Errors
    /// Returns an error if encryption fails (implementation-defined).
    async fn encrypt_with_context(&self, data: &[u8], ctx: &CryptoContext) -> Result<Self::Output>;

    /// Encrypts multiple data chunks in batch.
    ///
    /// # Errors
    /// Returns an error if any encryption fails (implementation-defined).
    async fn encrypt_batch(
        &self,
        data: &[&[u8]],
    ) -> std::result::Result<Vec<Self::Output>, Self::Error>;
}

/// Async version of [`Decryptable`] for async cryptographic operations.
#[async_trait]
pub trait AsyncDecryptable: Send + Sync {
    /// The output type of decryption operations.
    type Output;
    /// The error type for decryption failures.
    type Error;

    /// Decrypts data asynchronously with default settings.
    ///
    /// # Errors
    /// Returns an error if decryption fails (implementation-defined).
    async fn decrypt(&self, encrypted: &[u8]) -> Result<Self::Output>;

    /// Decrypts data asynchronously with the provided context.
    ///
    /// # Errors
    /// Returns an error if decryption fails (implementation-defined).
    async fn decrypt_with_context(
        &self,
        encrypted: &[u8],
        ctx: &CryptoContext,
    ) -> Result<Self::Output>;

    /// Decrypts multiple ciphertexts in batch.
    ///
    /// # Errors
    /// Returns an error if any decryption fails (implementation-defined).
    async fn decrypt_batch(
        &self,
        encrypted: &[&[u8]],
    ) -> std::result::Result<Vec<Self::Output>, Self::Error>;
}

/// Async version of [`Signable`] for async cryptographic operations.
#[async_trait]
pub trait AsyncSignable: Send + Sync {
    /// The output type of signing operations.
    type Output;
    /// The error type for signing failures.
    type Error;

    /// Signs a message asynchronously with default settings.
    ///
    /// # Errors
    /// Returns an error if signing fails (implementation-defined).
    async fn sign(&self, message: &[u8]) -> Result<Self::Output>;

    /// Signs a message asynchronously with the provided context.
    ///
    /// # Errors
    /// Returns an error if signing fails (implementation-defined).
    async fn sign_with_context(&self, message: &[u8], ctx: &CryptoContext) -> Result<Self::Output>;

    /// Signs multiple messages in batch.
    ///
    /// # Errors
    /// Returns an error if any signing fails (implementation-defined).
    async fn sign_batch(
        &self,
        messages: &[&[u8]],
    ) -> std::result::Result<Vec<Self::Output>, Self::Error>;
}

/// Async version of [`Verifiable`] for async cryptographic operations.
#[async_trait]
pub trait AsyncVerifiable: Send + Sync {
    /// The error type for verification failures.
    type Error;

    /// Verifies a signature asynchronously.
    ///
    /// # Errors
    /// Returns an error if verification fails (implementation-defined).
    async fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<bool, Self::Error>;

    /// Verifies a signature asynchronously with the provided context.
    ///
    /// # Errors
    /// Returns an error if verification fails (implementation-defined).
    async fn verify_with_context(
        &self,
        message: &[u8],
        signature: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<bool, Self::Error>;

    /// Verifies multiple signatures in batch.
    ///
    /// # Errors
    /// Returns an error if any verification fails (implementation-defined).
    async fn verify_batch(
        &self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
    ) -> std::result::Result<Vec<bool>, Self::Error>;
}

/// Trait for zero-trust authentication with challenge-response proofs.
pub trait ZeroTrustAuthenticable {
    /// The proof type generated by this authenticator.
    type Proof;
    /// The error type for authentication failures.
    type Error;

    /// Generates a proof for the given challenge.
    ///
    /// # Errors
    /// Returns an error if proof generation fails (implementation-defined).
    fn generate_proof(&self, challenge: &[u8]) -> std::result::Result<Self::Proof, Self::Error>;

    /// Verifies a proof against the given challenge.
    ///
    /// # Errors
    /// Returns an error if verification fails (implementation-defined).
    fn verify_proof(
        &self,
        proof: &Self::Proof,
        challenge: &[u8],
    ) -> std::result::Result<bool, Self::Error>;
}

/// Trait for proof-of-possession verification.
pub trait ProofOfPossession {
    /// The proof-of-possession type.
    type Pop;
    /// The error type for PoP operations.
    type Error;

    /// Generates a proof of possession.
    ///
    /// # Errors
    /// Returns an error if PoP generation fails (implementation-defined).
    fn generate_pop(&self) -> std::result::Result<Self::Pop, Self::Error>;

    /// Verifies a proof of possession.
    ///
    /// # Errors
    /// Returns an error if verification fails (implementation-defined).
    fn verify_pop(&self, pop: &Self::Pop) -> std::result::Result<bool, Self::Error>;
}

/// Trait for continuous session verification.
pub trait ContinuousVerifiable {
    /// The error type for verification failures.
    type Error;

    /// Checks the current verification status of the session.
    ///
    /// # Errors
    /// Returns an error if status check fails (implementation-defined).
    fn verify_continuously(&self) -> std::result::Result<VerificationStatus, Self::Error>;

    /// Performs reauthentication to refresh the session.
    ///
    /// # Errors
    /// Returns an error if reauthentication fails (implementation-defined).
    fn reauthenticate(&self) -> std::result::Result<(), Self::Error>;
}

/// Status of continuous verification.
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationStatus {
    /// Session is verified and valid.
    Verified,
    /// Session has expired.
    Expired,
    /// Verification failed.
    Failed,
    /// Verification is pending.
    Pending,
}

impl VerificationStatus {
    /// Returns `true` if the status is [`Verified`](VerificationStatus::Verified).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Trait for hardware-aware operations.
pub trait HardwareAware {
    /// The error type for hardware operations.
    type Error;

    /// Detects available hardware accelerators.
    fn detect_hardware(&self) -> HardwareInfo;

    /// Routes an operation to the best available hardware.
    ///
    /// # Errors
    /// Returns an error if the operation fails (implementation-defined).
    fn route_to_best_hardware<F, R>(&self, f: F) -> std::result::Result<R, Self::Error>
    where
        F: FnOnce(&dyn HardwareAccelerator) -> std::result::Result<R, Self::Error>;
}

/// Trait for hardware accelerator implementations.
pub trait HardwareAccelerator {
    /// Returns the human-readable name of the accelerator.
    fn name(&self) -> &str;
    /// Returns the type of hardware.
    fn hardware_type(&self) -> HardwareType;
    /// Returns whether the accelerator is currently available.
    fn is_available(&self) -> bool;
}

/// Type of hardware accelerator.
#[derive(Debug, Clone, PartialEq)]
pub enum HardwareType {
    /// CPU with SIMD extensions.
    Cpu,
    /// GPU acceleration.
    Gpu,
    /// FPGA acceleration.
    Fpga,
    /// TPM hardware security module.
    Tpu,
    /// Intel SGX enclave.
    Sgx,
}

/// Information about available hardware.
#[derive(Debug, Clone)]
pub struct HardwareInfo {
    /// List of available hardware accelerators.
    pub available_accelerators: Vec<HardwareType>,
    /// Preferred accelerator based on capabilities.
    pub preferred_accelerator: Option<HardwareType>,
    /// Hardware capabilities.
    pub capabilities: HardwareCapabilities,
}

/// Hardware capability information.
#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    /// Whether SIMD instructions are supported.
    pub simd_support: bool,
    /// Whether AES-NI instructions are available.
    pub aes_ni: bool,
    /// Number of available threads.
    pub threads: usize,
    /// Available memory in bytes.
    pub memory: usize,
}

impl HardwareInfo {
    /// Returns the best available accelerator, preferring the configured preference.
    #[must_use]
    pub fn best_accelerator(&self) -> Option<&HardwareType> {
        self.preferred_accelerator.as_ref().or_else(|| self.available_accelerators.first())
    }

    /// Returns a human-readable summary of the hardware info.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Available: {:?}, Preferred: {:?}, Capabilities: {:?}",
            self.available_accelerators, self.preferred_accelerator, self.capabilities
        )
    }
}

/// Trait for cryptographic scheme selection.
pub trait SchemeSelector {
    /// The error type for selection failures.
    type Error;

    /// Selects an encryption scheme based on data and context.
    ///
    /// # Errors
    /// Returns an error if scheme selection fails (implementation-defined).
    fn select_encryption_scheme(
        &self,
        data: &[u8],
        ctx: &CryptoContext,
    ) -> std::result::Result<String, Self::Error>;

    /// Selects a signature scheme based on context.
    ///
    /// # Errors
    /// Returns an error if scheme selection fails (implementation-defined).
    fn select_signature_scheme(
        &self,
        ctx: &CryptoContext,
    ) -> std::result::Result<String, Self::Error>;

    /// Analyzes characteristics of the input data.
    fn analyze_data_characteristics(&self, data: &[u8]) -> DataCharacteristics;
}

/// Characteristics of data for scheme selection.
#[derive(Debug, Clone)]
pub struct DataCharacteristics {
    /// Size of the data in bytes.
    pub size: usize,
    /// Estimated entropy (0.0 to 8.0 bits per byte).
    pub entropy: f64,
    /// Detected pattern type.
    pub pattern_type: PatternType,
}

/// Type of pattern detected in data.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    /// High-entropy random data.
    Random,
    /// Data with detectable structure.
    Structured,
    /// Data with repetitive patterns.
    Repetitive,
    /// Human-readable text.
    Text,
    /// Binary data without clear patterns.
    Binary,
}
