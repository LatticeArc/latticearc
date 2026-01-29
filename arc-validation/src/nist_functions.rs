#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: NIST SP 800-106 randomized hashing implementation.
// - Hash computation with fixed block sizes
// - Binary data manipulation with known structures
// - Test infrastructure for signature validation
// - Result<> used for API consistency across functions
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::should_implement_trait)]

//! # NIST SP 800-106 Randomized Hashing for Digital Signatures
//!
//! Implementation of randomized hashing techniques for digital signatures
//! according to NIST SP 800-106 "Recommendation for Randomized Hashing
//! for Digital Signatures".

use arc_prelude::error::{LatticeArcError, Result};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Randomized hashing modes
#[derive(Clone, Debug, PartialEq)]
pub enum RandomizedHashMode {
    /// No randomization (standard hashing)
    None,
    /// Random salt prepended to message
    SaltPrefix,
    /// Random salt appended to message
    SaltSuffix,
    /// Random salt inserted at multiple positions
    SaltDistributed,
}

/// Randomized hash configuration
#[derive(Clone, Debug)]
pub struct RandomizedHashConfig {
    /// Hash algorithm to use
    pub algorithm: String,
    /// Randomization mode
    pub mode: RandomizedHashMode,
    /// Salt length in bytes
    pub salt_length: usize,
    /// Number of salt insertions (for distributed mode)
    pub salt_insertions: usize,
}

impl Default for RandomizedHashConfig {
    fn default() -> Self {
        Self {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltPrefix,
            salt_length: 32,
            salt_insertions: 3,
        }
    }
}

/// Randomized hash generator
pub struct RandomizedHasher {
    config: RandomizedHashConfig,
}

impl RandomizedHasher {
    /// Create a new randomized hasher
    #[must_use]
    pub fn new(config: RandomizedHashConfig) -> Self {
        Self { config }
    }

    /// Create hasher with default configuration
    #[must_use]
    pub fn default() -> Self {
        Self::new(RandomizedHashConfig::default())
    }

    /// Generate randomized hash of a message.
    ///
    /// # Errors
    /// Returns an error if salt generation fails or the hash algorithm is unsupported.
    pub fn hash(&self, message: &[u8]) -> Result<RandomizedHash> {
        let salt = self.generate_salt()?;
        let randomized_message = self.apply_randomization(message, &salt)?;

        let hash = self.compute_hash(&randomized_message)?;

        Ok(RandomizedHash {
            hash,
            salt,
            algorithm: self.config.algorithm.clone(),
            mode: self.config.mode.clone(),
        })
    }

    /// Verify a randomized hash.
    ///
    /// # Errors
    /// Returns an error if the hash algorithm is unsupported or hash computation fails.
    pub fn verify(&self, message: &[u8], randomized_hash: &RandomizedHash) -> Result<bool> {
        if randomized_hash.algorithm != self.config.algorithm
            || randomized_hash.mode != self.config.mode
        {
            return Ok(false);
        }

        // Use the salt from the randomized_hash to re-compute
        let randomized_message = self.apply_randomization(message, &randomized_hash.salt)?;
        let computed_hash = self.compute_hash(&randomized_message)?;

        Ok(computed_hash == randomized_hash.hash)
    }

    /// Compute hash for the given data using the configured algorithm
    fn compute_hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.config.algorithm.as_str() {
            "SHA-256" => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            "SHA-384" => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            "SHA-512" => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(LatticeArcError::InvalidKey(format!(
                "Unsupported hash algorithm: {}",
                self.config.algorithm
            ))),
        }
    }

    /// Generate random salt
    fn generate_salt(&self) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; self.config.salt_length];
        if !salt.is_empty() {
            rand::thread_rng().fill_bytes(&mut salt);

            // Ensure salt is not all zeros (basic sanity check)
            if salt.iter().all(|&x| x == 0)
                && let Some(first_byte) = salt.get_mut(0)
            {
                *first_byte = 1; // Force at least one non-zero byte
            }
        }

        Ok(salt)
    }

    /// Apply randomization to message based on mode
    fn apply_randomization(&self, message: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        match self.config.mode {
            RandomizedHashMode::None => Ok(message.to_vec()),
            RandomizedHashMode::SaltPrefix => {
                let mut result = Vec::with_capacity(salt.len() + message.len());
                result.extend_from_slice(salt);
                result.extend_from_slice(message);
                Ok(result)
            }
            RandomizedHashMode::SaltSuffix => {
                let mut result = Vec::with_capacity(message.len() + salt.len());
                result.extend_from_slice(message);
                result.extend_from_slice(salt);
                Ok(result)
            }
            RandomizedHashMode::SaltDistributed => self.apply_distributed_salt(message, salt),
        }
    }

    /// Apply distributed salt randomization
    fn apply_distributed_salt(&self, message: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        if message.is_empty() {
            return Ok(salt.to_vec());
        }

        let mut result = Vec::new();
        let salt_chunks = self.split_salt_into_chunks(salt)?;

        // Distribute salt chunks throughout the message
        let message_parts = self.split_message_into_parts(message);

        for (i, part) in message_parts.iter().enumerate() {
            result.extend_from_slice(part);

            // Insert salt chunk if available
            if let Some(salt_chunk) = salt_chunks.get(i) {
                result.extend_from_slice(salt_chunk);
            }
        }

        Ok(result)
    }

    /// Split salt into chunks for distributed mode
    fn split_salt_into_chunks(&self, salt: &[u8]) -> Result<Vec<Vec<u8>>> {
        let chunk_size = std::cmp::max(1, salt.len() / self.config.salt_insertions);
        let mut chunks = Vec::new();

        for i in 0..self.config.salt_insertions {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, salt.len());
            if start < salt.len() {
                chunks.push(salt[start..end].to_vec());
            }
        }

        // Add any remaining salt to the last chunk
        if chunks.len() < self.config.salt_insertions && !salt.is_empty() {
            let remaining_start = chunks.len() * chunk_size;
            if remaining_start < salt.len() {
                chunks.push(salt[remaining_start..].to_vec());
            }
        }

        Ok(chunks)
    }

    /// Split message into parts for distributed salt insertion
    fn split_message_into_parts(&self, message: &[u8]) -> Vec<Vec<u8>> {
        if message.is_empty() {
            return vec![vec![]];
        }

        let num_parts = self.config.salt_insertions + 1;
        let part_size = message.len() / num_parts;
        let mut parts = Vec::new();
        let mut start = 0;

        for i in 0..num_parts {
            let end = if i == num_parts - 1 { message.len() } else { start + part_size };

            parts.push(message[start..end].to_vec());
            start = end;
        }

        parts
    }
}

/// Randomized hash result
#[derive(Clone, Debug, PartialEq)]
pub struct RandomizedHash {
    /// The computed hash value
    pub hash: Vec<u8>,
    /// The salt used for randomization
    pub salt: Vec<u8>,
    /// Hash algorithm used
    pub algorithm: String,
    /// Randomization mode used
    pub mode: RandomizedHashMode,
}

impl RandomizedHash {
    /// Get hash as hex string
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex::encode(&self.hash)
    }

    /// Get salt as hex string
    #[must_use]
    pub fn salt_hex(&self) -> String {
        hex::encode(&self.salt)
    }
}

/// Convenience functions for randomized hashing
pub struct RandomizedHashing;

impl RandomizedHashing {
    /// Create a randomized hash with default settings.
    ///
    /// # Errors
    /// Returns an error if salt generation fails or hash computation fails.
    pub fn hash_message(message: &[u8]) -> Result<RandomizedHash> {
        let hasher = RandomizedHasher::default();
        hasher.hash(message)
    }

    /// Create a randomized hash with custom configuration.
    ///
    /// # Errors
    /// Returns an error if salt generation fails or the hash algorithm is unsupported.
    pub fn hash_message_with_config(
        message: &[u8],
        config: RandomizedHashConfig,
    ) -> Result<RandomizedHash> {
        let hasher = RandomizedHasher::new(config);
        hasher.hash(message)
    }

    /// Verify a randomized hash.
    ///
    /// # Errors
    /// Returns an error if the hash algorithm is unsupported or hash computation fails.
    pub fn verify_hash(message: &[u8], hash: &RandomizedHash) -> Result<bool> {
        let config = RandomizedHashConfig {
            algorithm: hash.algorithm.clone(),
            mode: hash.mode.clone(),
            salt_length: hash.salt.len(),
            salt_insertions: 3, // Default value
        };

        let hasher = RandomizedHasher::new(config);
        hasher.verify(message, hash)
    }

    /// Get recommended configuration for different security levels
    #[must_use]
    pub fn recommended_config(security_level: usize) -> RandomizedHashConfig {
        match security_level {
            128 => RandomizedHashConfig {
                algorithm: "SHA-256".to_string(),
                mode: RandomizedHashMode::SaltPrefix,
                salt_length: 16,
                salt_insertions: 2,
            },
            192 => RandomizedHashConfig {
                algorithm: "SHA-384".to_string(),
                mode: RandomizedHashMode::SaltDistributed,
                salt_length: 24,
                salt_insertions: 3,
            },
            256 => RandomizedHashConfig {
                algorithm: "SHA-512".to_string(),
                mode: RandomizedHashMode::SaltDistributed,
                salt_length: 32,
                salt_insertions: 4,
            },
            _ => RandomizedHashConfig::default(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_randomized_hash_basic() {
        let message = b"Hello, randomized hashing!";
        let hash1 = RandomizedHashing::hash_message(message).unwrap();
        let hash2 = RandomizedHashing::hash_message(message).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1.hash, hash2.hash);
        assert_ne!(hash1.salt, hash2.salt);

        // But verification should work
        assert!(RandomizedHashing::verify_hash(message, &hash1).unwrap());
        assert!(RandomizedHashing::verify_hash(message, &hash2).unwrap());
    }

    #[test]
    fn test_randomized_hash_modes() {
        let message = b"test message";
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltPrefix,
            salt_length: 8,
            salt_insertions: 2,
        };

        let hasher = RandomizedHasher::new(config);
        let hash = hasher.hash(message).unwrap();

        assert_eq!(hash.algorithm, "SHA-256");
        assert_eq!(hash.salt.len(), 8);
        assert_eq!(hash.hash.len(), 32); // SHA-256 output length
    }

    #[test]
    fn test_distributed_salt_mode() {
        let message = b"distributed salt test";
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltDistributed,
            salt_length: 12,
            salt_insertions: 3,
        };

        let hasher = RandomizedHasher::new(config);
        let hash = hasher.hash(message).unwrap();

        // Verification should work
        assert!(hasher.verify(message, &hash).unwrap());
    }

    #[test]
    fn test_different_messages_different_hashes() {
        let message1 = b"message 1";
        let message2 = b"message 2";

        let hash1 = RandomizedHashing::hash_message(message1).unwrap();
        let hash2 = RandomizedHashing::hash_message(message2).unwrap();

        assert_ne!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_hash_verification_failure() {
        let message1 = b"message 1";
        let message2 = b"message 2";

        let hash = RandomizedHashing::hash_message(message1).unwrap();

        // Verification with wrong message should fail
        assert!(!RandomizedHashing::verify_hash(message2, &hash).unwrap());
    }

    #[test]
    fn test_security_level_configs() {
        let config128 = RandomizedHashing::recommended_config(128);
        assert_eq!(config128.algorithm, "SHA-256");
        assert_eq!(config128.salt_length, 16);

        let config256 = RandomizedHashing::recommended_config(256);
        assert_eq!(config256.algorithm, "SHA-512");
        assert_eq!(config256.salt_length, 32);
        assert_eq!(config256.mode, RandomizedHashMode::SaltDistributed);
    }

    #[test]
    fn test_no_randomization_mode() {
        let message = b"test message";
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::None,
            salt_length: 0,
            salt_insertions: 0,
        };

        let hasher = RandomizedHasher::new(config);
        let hash = hasher.hash(message).unwrap();

        // Without randomization, should produce standard SHA-256
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(message);
        let expected = expected_hasher.finalize();

        assert_eq!(hash.hash, expected.to_vec());
        assert!(hash.salt.is_empty());
    }

    #[test]
    fn test_randomized_hash_hex_output() {
        let message = b"test";
        let hash = RandomizedHashing::hash_message(message).unwrap();

        let hash_hex = hash.hash_hex();
        let salt_hex = hash.salt_hex();

        assert!(!hash_hex.is_empty());
        assert!(!salt_hex.is_empty());

        // Hex strings should be valid
        assert!(hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(salt_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
