#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Basic types for AI-optimized cryptographic defaults

use crate::unified_api::types::HomomorphicScheme;

/// ML-KEM variant selection for key encapsulation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemVariant {
    pub fn key_size(&self) -> usize {
        match self {
            MlKemVariant::MlKem512 => 800,
            MlKemVariant::MlKem768 => 1184,
            MlKemVariant::MlKem1024 => 1568,
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            MlKemVariant::MlKem512 => 768,
            MlKemVariant::MlKem768 => 1088,
            MlKemVariant::MlKem1024 => 1568,
        }
    }

    pub fn shared_secret_size(&self) -> usize {
        32
    }
}

/// Hash function selection for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
}

impl HashFunction {
    pub fn output_size(&self) -> usize {
        match self {
            HashFunction::Sha3_256 => 32,
            HashFunction::Sha3_384 => 48,
            HashFunction::Sha3_512 => 64,
            HashFunction::Shake128 => 32,
            HashFunction::Shake256 => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            HashFunction::Sha3_256 | HashFunction::Sha3_384 | HashFunction::Sha3_512 => 136,
            HashFunction::Shake128 | HashFunction::Shake256 => 168,
        }
    }
}

/// Fully Homomorphic Encryption scheme selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FheScheme {
    Paillier,
    BFV,
    CKKS,
    TFHE,
}

impl FheScheme {
    pub fn as_homomorphic_scheme(&self) -> HomomorphicScheme {
        match self {
            FheScheme::Paillier => HomomorphicScheme::Paillier,
            FheScheme::BFV => HomomorphicScheme::BFV,
            FheScheme::CKKS => HomomorphicScheme::CKKS,
            FheScheme::TFHE => HomomorphicScheme::TFHE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_variant_sizes() {
        assert_eq!(MlKemVariant::MlKem512.key_size(), 800);
        assert_eq!(MlKemVariant::MlKem768.key_size(), 1184);
        assert_eq!(MlKemVariant::MlKem1024.key_size(), 1568);
    }

    #[test]
    fn test_hash_function_sizes() {
        assert_eq!(HashFunction::Sha3_256.output_size(), 32);
        assert_eq!(HashFunction::Sha3_384.output_size(), 48);
        assert_eq!(HashFunction::Sha3_512.output_size(), 64);
    }

    #[test]
    fn test_fhe_scheme_conversion() {
        assert!(matches!(
            FheScheme::CKKS.as_homomorphic_scheme(),
            HomomorphicScheme::CKKS
        ));
    }
}
