#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Algorithm parameter configuration for AI-optimized defaults

use super::types::{FheScheme, HashFunction, MlKemVariant};

/// Key Encapsulation Mechanism parameters
#[derive(Debug, Clone)]
pub struct KemParams {
    pub ml_kem_variant: MlKemVariant,
    pub classical_fallback: bool,
}

impl KemParams {
    pub fn ml_kem_768() -> Self {
        Self {
            ml_kem_variant: MlKemVariant::MlKem768,
            classical_fallback: true,
        }
    }

    pub fn ml_kem_1024() -> Self {
        Self {
            ml_kem_variant: MlKemVariant::MlKem1024,
            classical_fallback: false,
        }
    }
}

/// Authenticated Encryption with Associated Data parameters
#[derive(Debug, Clone)]
pub struct AeadParams {
    pub key_size: usize,
    pub nonce_size: usize,
    pub tag_size: usize,
    pub associated_data: bool,
}

impl AeadParams {
    pub fn aes_gcm() -> Self {
        Self {
            key_size: 32,
            nonce_size: 12,
            tag_size: 16,
            associated_data: true,
        }
    }

    pub fn aes_256_gcm() -> Self {
        Self {
            key_size: 32,
            nonce_size: 12,
            tag_size: 16,
            associated_data: true,
        }
    }

    pub fn aes_384_gcm() -> Self {
        Self {
            key_size: 48,
            nonce_size: 12,
            tag_size: 32,
            associated_data: true,
        }
    }

    pub fn chacha20_poly1305() -> Self {
        Self {
            key_size: 32,
            nonce_size: 12,
            tag_size: 16,
            associated_data: false,
        }
    }
}

/// Hash function parameters
#[derive(Debug, Clone)]
pub struct HashParams {
    pub hash_function: HashFunction,
    pub output_size: usize,
    pub rounds: usize,
}

impl HashParams {
    pub fn sha3_256() -> Self {
        Self {
            hash_function: HashFunction::Sha3_256,
            output_size: 32,
            rounds: 24,
        }
    }

    pub fn sha3_384() -> Self {
        Self {
            hash_function: HashFunction::Sha3_384,
            output_size: 48,
            rounds: 24,
        }
    }

    pub fn sha3_512() -> Self {
        Self {
            hash_function: HashFunction::Sha3_512,
            output_size: 64,
            rounds: 24,
        }
    }
}

/// Fully Homomorphic Encryption parameters
#[derive(Debug, Clone)]
pub struct FheParams {
    pub fhe_scheme: FheScheme,
    pub security_level: u64,
    pub plaintext_slot_size: usize,
}

impl FheParams {
    pub fn paillier() -> Self {
        Self {
            fhe_scheme: FheScheme::Paillier,
            security_level: 128,
            plaintext_slot_size: 2048,
        }
    }

    pub fn ckks_ml() -> Self {
        Self {
            fhe_scheme: FheScheme::CKKS,
            security_level: 128,
            plaintext_slot_size: 8192,
        }
    }

    pub fn bfv() -> Self {
        Self {
            fhe_scheme: FheScheme::BFV,
            security_level: 128,
            plaintext_slot_size: 4096,
        }
    }
}

/// Combined algorithm parameters for a crypto configuration
#[derive(Debug, Clone)]
pub struct AlgorithmParams {
    pub kem_params: KemParams,
    pub aead_params: AeadParams,
    pub hash_params: HashParams,
    pub fhe_params: Option<FheParams>,
}

impl AlgorithmParams {
    pub fn hybrid_messaging() -> Self {
        Self {
            kem_params: KemParams::ml_kem_768(),
            aead_params: AeadParams::aes_gcm(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn hybrid_database() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_gcm(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn ml_fhe() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_gcm(),
            hash_params: HashParams::sha3_256(),
            fhe_params: Some(FheParams::ckks_ml()),
        }
    }

    pub fn healthcare() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_256_gcm(),
            hash_params: HashParams::sha3_384(),
            fhe_params: None,
        }
    }

    pub fn financial() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_384_gcm(),
            hash_params: HashParams::sha3_512(),
            fhe_params: None,
        }
    }

    pub fn high_security() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_384_gcm(),
            hash_params: HashParams::sha3_512(),
            fhe_params: None,
        }
    }

    pub fn performance() -> Self {
        Self {
            kem_params: KemParams::ml_kem_768(),
            aead_params: AeadParams::chacha20_poly1305(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn general_purpose() -> Self {
        Self {
            kem_params: KemParams::ml_kem_768(),
            aead_params: AeadParams::aes_gcm(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn encrypted_messaging_e2e() -> Self {
        Self {
            kem_params: KemParams {
                ml_kem_variant: MlKemVariant::MlKem768,
                classical_fallback: true,
            },
            aead_params: AeadParams::aes_256_gcm(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn file_storage() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_256_gcm(),
            hash_params: HashParams::sha3_384(),
            fhe_params: None,
        }
    }

    pub fn real_time_stream() -> Self {
        Self {
            kem_params: KemParams::ml_kem_768(),
            aead_params: AeadParams::chacha20_poly1305(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn iot_edge() -> Self {
        Self {
            kem_params: KemParams {
                ml_kem_variant: MlKemVariant::MlKem512,
                classical_fallback: true,
            },
            aead_params: AeadParams::chacha20_poly1305(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn multi_party_computation() -> Self {
        Self {
            kem_params: KemParams::ml_kem_1024(),
            aead_params: AeadParams::aes_gcm(),
            hash_params: HashParams::sha3_384(),
            fhe_params: None,
        }
    }

    pub fn blockchain_web3() -> Self {
        Self {
            kem_params: KemParams {
                ml_kem_variant: MlKemVariant::MlKem768,
                classical_fallback: false,
            },
            aead_params: AeadParams::aes_256_gcm(),
            hash_params: HashParams::sha3_384(),
            fhe_params: None,
        }
    }

    pub fn high_throughput_batch() -> Self {
        Self {
            kem_params: KemParams::ml_kem_768(),
            aead_params: AeadParams::aes_256_gcm(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }

    pub fn small_payload() -> Self {
        Self {
            kem_params: KemParams {
                ml_kem_variant: MlKemVariant::MlKem512,
                classical_fallback: true,
            },
            aead_params: AeadParams::chacha20_poly1305(),
            hash_params: HashParams::sha3_256(),
            fhe_params: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_params_variants() {
        let params = AlgorithmParams::hybrid_messaging();
        assert!(matches!(
            params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem768
        ));
        assert!(params.fhe_params.is_none());

        let params = AlgorithmParams::ml_fhe();
        assert!(matches!(
            params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem1024
        ));
        assert!(params.fhe_params.is_some());
        assert!(matches!(
            params.fhe_params.as_ref().map(|p| p.fhe_scheme),
            Some(FheScheme::CKKS)
        ));
    }

    #[test]
    fn test_new_algorithm_params() {
        let e2e_params = AlgorithmParams::encrypted_messaging_e2e();
        assert!(matches!(
            e2e_params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem768
        ));

        let file_params = AlgorithmParams::file_storage();
        assert!(matches!(
            file_params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem1024
        ));

        let iot_params = AlgorithmParams::iot_edge();
        assert!(matches!(
            iot_params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem512
        ));

        let small_params = AlgorithmParams::small_payload();
        assert!(matches!(
            small_params.kem_params.ml_kem_variant,
            MlKemVariant::MlKem512
        ));
    }
}
