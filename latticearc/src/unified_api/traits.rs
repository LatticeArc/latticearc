#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Traits for cryptographic operations.
//!
//! This module defines the core traits used throughout LatticeArc for encryption,
//! decryption, signing, verification, key derivation, hashing, zero-trust authentication,
//! and hardware acceleration.

use std::future::Future;
use std::pin::Pin;
use subtle::Choice;

use crate::unified_api::{
    CryptoScheme,
    error::{CryptoError, HardwareError},
    types::{CryptoContext, DataCharacteristics, HardwareInfo, HardwareType, VerificationStatus},
};

/// Trait for data that can be encrypted.
///
/// This trait provides encryption capabilities with optional context support.
///
/// # Type Parameters
///
/// * `Output` - The type of the encrypted output
/// * `Error` - The error type that can occur during encryption
///
/// # Examples
///
/// ```rust
/// use latticearc::unified_api::traits::Encryptable;
/// use latticearc::unified_api::types::CryptoContext;
///
/// struct MyData {
///     content: Vec<u8>,
/// }
///
/// impl Encryptable for MyData {
///     type Output = Vec<u8>;
///     type Error = latticearc::unified_api::error::CryptoError;
///
///     fn encrypt_with_context(
///         &self,
///         data: &[u8],
///         ctx: &CryptoContext,
///     ) -> Result<Self::Output, Self::Error> {
///         // Implementation
///         Ok(vec![])
///     }
/// }
/// ```
pub trait Encryptable {
    type Output;
    type Error;

    /// Encrypt data with default context.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted output or an error
    fn encrypt(&self, data: &[u8]) -> Result<Self::Output, Self::Error> {
        self.encrypt_with_context(data, &CryptoContext::default())
    }

    /// Encrypt data with custom context.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// The encrypted output or an error
    fn encrypt_with_context(
        &self,
        data: &[u8],
        ctx: &CryptoContext,
    ) -> Result<Self::Output, Self::Error>;
}

/// Trait for data that can be decrypted.
///
/// This trait provides decryption capabilities with optional context support.
///
/// # Type Parameters
///
/// * `Output` - The type of the decrypted output
/// * `Error` - The error type that can occur during decryption
pub trait Decryptable {
    type Output;
    type Error;

    /// Decrypt data with default context.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted data to decrypt
    ///
    /// # Returns
    ///
    /// The decrypted output or an error
    fn decrypt(&self, encrypted: &[u8]) -> Result<Self::Output, Self::Error> {
        self.decrypt_with_context(encrypted, &CryptoContext::default())
    }

    /// Decrypt data with custom context.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted data to decrypt
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// The decrypted output or an error
    fn decrypt_with_context(
        &self,
        encrypted: &[u8],
        ctx: &CryptoContext,
    ) -> Result<Self::Output, Self::Error>;
}

/// Trait for data that can be signed.
///
/// This trait provides digital signature capabilities.
///
/// # Type Parameters
///
/// * `Output` - The type of the signed output
/// * `Error` - The error type that can occur during signing
pub trait Signable {
    type Output;
    type Error;

    /// Sign a message with default context.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signed output or an error
    fn sign(&self, message: &[u8]) -> Result<Self::Output, Self::Error> {
        self.sign_with_context(message, &CryptoContext::default())
    }

    /// Sign a message with custom context.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// The signed output or an error
    fn sign_with_context(
        &self,
        message: &[u8],
        ctx: &CryptoContext,
    ) -> Result<Self::Output, Self::Error>;
}

/// Trait for verifying data signatures.
///
/// This trait provides signature verification capabilities.
///
/// # Type Parameters
///
/// * `Error` - The error type that can occur during verification
pub trait Verifiable {
    type Error;

    /// Verify a signature with default context.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// A `Choice` indicating if the signature is valid (constant-time)
    fn verify(&self, message: &[u8], signature: &[u8]) -> Choice {
        self.verify_with_context(message, signature, &CryptoContext::default())
    }

    /// Verify a signature with custom context.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// A `Choice` indicating if the signature is valid (constant-time)
    fn verify_with_context(&self, message: &[u8], signature: &[u8], ctx: &CryptoContext) -> Choice;

    /// Verify a signature and return a result.
    ///
    /// This is a convenience method that converts the `Choice` to a `Result`.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(VerificationError)` otherwise
    fn verify_result(&self, message: &[u8], signature: &[u8]) -> Result<(), Self::Error> {
        self.verify_result_with_context(message, signature, &CryptoContext::default())
    }

    /// Verify a signature with custom context and return a result.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(VerificationError)` otherwise
    fn verify_result_with_context(
        &self,
        message: &[u8],
        signature: &[u8],
        ctx: &CryptoContext,
    ) -> Result<(), Self::Error>;
}

/// Trait for deriving keys from input data.
///
/// This trait provides key derivation capabilities using KDFs like HKDF, PBKDF2, Argon2, Scrypt.
///
/// # Type Parameters
///
/// * `Output` - The type of the derived key output
/// * `Error` - The error type that can occur during key derivation
pub trait KeyDerivable {
    type Output;
    type Error;

    /// Derive a key from input data.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data (e.g., password)
    /// * `info` - Additional info for key derivation
    /// * `length` - The desired key length in bytes
    ///
    /// # Returns
    ///
    /// The derived key or an error
    fn derive_key(
        &self,
        input: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Self::Output, Self::Error>;

    /// Derive a key from a password.
    ///
    /// This is a convenience method for password-based key derivation.
    ///
    /// # Arguments
    ///
    /// * `password` - The password as a string
    /// * `salt` - The salt for key derivation
    /// * `length` - The desired key length in bytes
    ///
    /// # Returns
    ///
    /// The derived key or an error
    fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        length: usize,
    ) -> Result<Self::Output, Self::Error> {
        self.derive_key(password.as_bytes(), salt, length)
    }
}

/// Trait for hashing data.
///
/// This trait provides hashing capabilities using various hash functions.
///
/// # Type Parameters
///
/// * `Output` - The type of the hash output
/// * `Error` - The error type that can occur during hashing
pub trait Hashable {
    type Output;
    type Error;

    /// Hash a single input.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// The hash output or an error
    fn hash(&self, data: &[u8]) -> Result<Self::Output, Self::Error>;

    /// Hash multiple inputs.
    ///
    /// This is useful for hashing structured data or multiple pieces of data.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The inputs to hash
    ///
    /// # Returns
    ///
    /// The hash output or an error
    fn hash_multiple(&self, inputs: &[&[u8]]) -> Result<Self::Output, Self::Error>;

    /// Compute HMAC of data with a key.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key
    /// * `data` - The data to compute HMAC for
    ///
    /// # Returns
    ///
    /// The HMAC output or an error
    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Self::Output, Self::Error>;
}

/// Trait for zero-trust authentication.
///
/// This trait provides zero-knowledge proof capabilities for authentication.
///
/// # Type Parameters
///
/// * `Proof` - The type of the zero-knowledge proof
/// * `Error` - The error type that can occur during proof generation/verification
pub trait ZeroTrustAuthenticable {
    type Proof;
    type Error;

    /// Generate a zero-knowledge proof for a challenge.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The challenge to generate a proof for
    ///
    /// # Returns
    ///
    /// The zero-knowledge proof or an error
    fn generate_proof(&self, challenge: &[u8]) -> Result<Self::Proof, Self::Error>;

    /// Verify a zero-knowledge proof with default context.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `challenge` - The original challenge
    ///
    /// # Returns
    ///
    /// A `Choice` indicating if the proof is valid (constant-time)
    fn verify_proof(&self, proof: &Self::Proof, challenge: &[u8]) -> Choice {
        self.verify_proof_with_context(proof, challenge, &CryptoContext::default())
    }

    /// Verify a zero-knowledge proof with custom context.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `challenge` - The original challenge
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// A `Choice` indicating if the proof is valid (constant-time)
    fn verify_proof_with_context(
        &self,
        proof: &Self::Proof,
        challenge: &[u8],
        ctx: &CryptoContext,
    ) -> Choice;

    /// Verify a proof and return a result.
    ///
    /// This is a convenience method that converts the `Choice` to a `Result`.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `challenge` - The original challenge
    ///
    /// # Returns
    ///
    /// `Ok(())` if the proof is valid, `Err(Self::Error)` otherwise
    fn verify_proof_result(&self, proof: &Self::Proof, challenge: &[u8])
    -> Result<(), Self::Error>;
}

/// Trait for proof of possession.
///
/// This trait provides proof of possession capabilities, proving that you possess a private key.
///
/// # Type Parameters
///
/// * `Pop` - The type of the proof of possession token
/// * `Error` - The error type that can occur during POP generation/verification
pub trait ProofOfPossession {
    type Pop;
    type Error;

    /// Generate a proof of possession.
    ///
    /// # Returns
    ///
    /// The proof of possession token or an error
    fn generate_pop(&self) -> Result<Self::Pop, Self::Error>;

    /// Verify a proof of possession with default context.
    ///
    /// # Arguments
    ///
    /// * `pop` - The proof of possession to verify
    ///
    /// # Returns
    ///
    /// A `Choice` indicating if the POP is valid (constant-time)
    fn verify_pop(&self, pop: &Self::Pop) -> Choice {
        self.verify_pop_with_context(pop, &CryptoContext::default())
    }

    /// Verify a proof of possession with custom context.
    ///
    /// # Arguments
    ///
    /// * `pop` - The proof of possession to verify
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// A `Choice` indicating if the POP is valid (constant-time)
    fn verify_pop_with_context(&self, pop: &Self::Pop, ctx: &CryptoContext) -> Choice;

    /// Verify a POP and return a result.
    ///
    /// This is a convenience method that converts the `Choice` to a `Result`.
    ///
    /// # Arguments
    ///
    /// * `pop` - The proof of possession to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the POP is valid, `Err(Self::Error)` otherwise
    fn verify_pop_result(&self, pop: &Self::Pop) -> Result<(), Self::Error>;
}

/// Trait for continuous verification.
///
/// This trait provides continuous verification capabilities for high-security scenarios.
///
/// # Type Parameters
///
/// * `Error` - The error type that can occur during verification
pub trait ContinuousVerifiable {
    type Error;

    /// Perform a single verification check.
    ///
    /// # Returns
    ///
    /// The verification status or an error
    fn verify_continuously(&self) -> Result<VerificationStatus, Self::Error>;

    /// Start a continuous verification session.
    ///
    /// # Returns
    ///
    /// The continuous session or an error
    fn start_continuous_verification(&self) -> Result<ContinuousSession, Self::Error>;
}

/// A continuous verification session.
///
/// This represents an ongoing continuous verification session with metadata.
#[derive(Debug)]
pub struct ContinuousSession {
    /// Unique session identifier
    pub session_id: Vec<u8>,
    /// Session start time (Unix timestamp in seconds)
    pub start_time: u64,
    /// Last verification time (Unix timestamp in seconds)
    pub last_verification: u64,
}

/// Trait for hardware-aware operations.
///
/// This trait provides capabilities for detecting hardware and routing operations to the best hardware.
///
/// # Type Parameters
///
/// * `Error` - The error type that can occur during hardware operations
pub trait HardwareAware {
    type Error;

    /// Detect available hardware capabilities.
    ///
    /// # Returns
    ///
    /// Information about available hardware
    fn detect_hardware(&self) -> HardwareInfo;

    /// Route an operation to the best available hardware.
    ///
    /// # Arguments
    ///
    /// * `f` - The operation to execute
    ///
    /// # Returns
    ///
    /// The result of the operation or an error
    fn route_to_best_hardware<F, R>(&self, f: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&dyn HardwareAccelerator) -> Result<R, Box<dyn std::error::Error>>;

    /// Force CPU usage (disable hardware acceleration).
    ///
    /// # Returns
    ///
    /// `true` if CPU-only mode is enabled
    fn force_cpu(&self) -> bool;

    /// Prefer a specific hardware type.
    ///
    /// # Arguments
    ///
    /// * `hardware` - The hardware type to prefer
    ///
    /// # Returns
    ///
    /// `true` if the hardware preference is set
    fn prefer_hardware(&self, hardware: HardwareType) -> bool;
}

/// Trait for hardware acceleration.
///
/// This trait provides capabilities for hardware-accelerated cryptographic operations.
pub trait HardwareAccelerator {
    /// Get the name of this accelerator.
    ///
    /// # Returns
    ///
    /// The accelerator name
    fn name(&self) -> &str;

    /// Get the hardware type of this accelerator.
    ///
    /// # Returns
    ///
    /// The hardware type
    fn hardware_type(&self) -> HardwareType;

    /// Check if this accelerator is available.
    ///
    /// # Returns
    ///
    /// `true` if the accelerator is available and ready to use
    fn is_available(&self) -> bool;

    /// Accelerate a cryptographic operation.
    ///
    /// # Arguments
    ///
    /// * `f` - The operation to execute
    ///
    /// # Returns
    ///
    /// The result of the operation or a hardware error
    fn accelerate<F, R>(&self, f: F) -> Result<R, HardwareError>
    where
        F: FnOnce() -> Result<R, HardwareError>;

    /// Benchmark an operation on this accelerator.
    ///
    /// # Arguments
    ///
    /// * `operation` - The name of the operation to benchmark
    ///
    /// # Returns
    ///
    /// The benchmark result (operations per second) or an error
    fn benchmark(&self, operation: &str) -> Result<f64, HardwareError>;
}

/// Async variant of [`Encryptable`].
pub trait AsyncEncryptable: Encryptable {
    /// Asynchronously encrypt data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    ///
    /// # Returns
    ///
    /// A future that resolves to the encrypted output or an error
    fn encrypt_async<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'a>>;

    /// Asynchronously encrypt data with context.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// A future that resolves to the encrypted output or an error
    fn encrypt_async_with_context<'a>(
        &'a self,
        data: &'a [u8],
        ctx: &'a CryptoContext,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'a>>;
}

/// Async variant of [`Decryptable`].
pub trait AsyncDecryptable: Decryptable {
    /// Asynchronously decrypt data.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted data to decrypt
    ///
    /// # Returns
    ///
    /// A future that resolves to the decrypted output or an error
    fn decrypt_async<'a>(
        &'a self,
        encrypted: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'a>>;

    /// Asynchronously decrypt data with context.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted data to decrypt
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// A future that resolves to the decrypted output or an error
    fn decrypt_async_with_context<'a>(
        &'a self,
        encrypted: &'a [u8],
        ctx: &'a CryptoContext,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'a>>;
}

/// Async variant of [`Signable`].
pub trait AsyncSignable: Signable {
    /// Asynchronously sign a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A future that resolves to the signed output or an error
    fn sign_async<'a>(
        &'a self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'a>>;

    /// Asynchronously sign a message with context.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// A future that resolves to the signed output or an error
    fn sign_async_with_context<'a>(
        &'a self,
        message: &'a [u8],
        ctx: &'a CryptoContext,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'a>>;
}

/// Async variant of [`Verifiable`].
pub trait AsyncVerifiable: Verifiable {
    /// Asynchronously verify a signature.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// A future that resolves to a `Choice` indicating validity
    fn verify_async<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Choice> + Send + 'a>>;

    /// Asynchronously verify a signature and return a result.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// A future that resolves to `Ok(())` if valid, `Err(Self::Error)` otherwise
    fn verify_async_result<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + 'a>>;
}

/// Trait for selecting cryptographic schemes.
///
/// This trait provides capabilities for automatically selecting the best cryptographic scheme based on context.
pub trait CryptoSchemeSelector {
    /// Select an encryption scheme based on data and context.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// The selected cryptographic scheme or an error
    fn select_encryption_scheme(
        &self,
        data: &[u8],
        ctx: &CryptoContext,
    ) -> Result<CryptoScheme, CryptoError>;

    /// Select a signature scheme based on context.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// The selected cryptographic scheme or an error
    fn select_signature_scheme(&self, ctx: &CryptoContext) -> Result<CryptoScheme, CryptoError>;

    /// Select a hash scheme based on context.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The cryptographic context
    ///
    /// # Returns
    ///
    /// The selected cryptographic scheme or an error
    fn select_hash_scheme(&self, ctx: &CryptoContext) -> Result<CryptoScheme, CryptoError>;

    /// Analyze data characteristics.
    ///
    /// This analyzes the data to determine its size, entropy, compressibility, and structure.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to analyze
    ///
    /// # Returns
    ///
    /// The data characteristics
    fn analyze_data_characteristics(&self, data: &[u8]) -> DataCharacteristics;
}

/// Trait for batch operations.
///
/// This trait provides capabilities for processing multiple items in batch.
///
/// # Type Parameters
///
/// * `T` - The item type to process
/// * `Output` - The output type
/// * `Error` - The error type
pub trait BatchOperation<T> {
    type Output;
    type Error;

    /// Process multiple items in batch.
    ///
    /// # Arguments
    ///
    /// * `items` - The items to process
    ///
    /// # Returns
    ///
    /// A vector of outputs or an error
    fn batch_process(&self, items: Vec<T>) -> Result<Vec<Self::Output>, Self::Error>;

    /// Process multiple items in parallel with batching.
    ///
    /// # Arguments
    ///
    /// * `items` - The items to process
    /// * `batch_size` - The batch size for parallel processing
    ///
    /// # Returns
    ///
    /// A vector of outputs or an error
    fn batch_process_parallel(
        &self,
        items: Vec<T>,
        batch_size: usize,
    ) -> Result<Vec<Self::Output>, Self::Error>;
}
