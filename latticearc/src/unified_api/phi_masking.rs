#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! PHI (Protected Health Information) Masking Engine
//!
//! Provides HIPAA-compliant data masking for healthcare applications.
//! This module enables secure analytics on healthcare data while
//! protecting personally identifiable health information.

use std::collections::HashMap;

/// PHI Masking Engine for healthcare data protection
#[derive(Debug, Clone)]
pub struct PhiMaskingEngine {
    /// Masking patterns for different PHI field types
    patterns: HashMap<PhiFieldType, MaskingPattern>,
    /// Whether to use deterministic masking (same input = same output)
    deterministic: bool,
    /// Salt for deterministic masking
    salt: Vec<u8>,
}

/// Types of PHI fields that can be masked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhiFieldType {
    /// Patient name
    Name,
    /// Social Security Number
    Ssn,
    /// Medical Record Number
    Mrn,
    /// Date of Birth
    DateOfBirth,
    /// Address
    Address,
    /// Phone Number
    PhoneNumber,
    /// Email Address
    Email,
    /// Insurance ID
    InsuranceId,
    /// Generic identifier
    GenericId,
}

/// Masking patterns for PHI fields
#[derive(Debug, Clone)]
pub enum MaskingPattern {
    /// Replace with asterisks, preserving length
    Asterisk,
    /// Replace with X characters, preserving length
    XMask,
    /// Preserve first N and last M characters
    PartialMask { prefix: usize, suffix: usize },
    /// Replace with a hash of the original value
    Hash,
    /// Replace with a random value of the same format
    Randomize,
    /// Generalize dates (e.g., just year)
    DateGeneralize,
}

impl Default for PhiMaskingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PhiMaskingEngine {
    /// Create a new PHI masking engine with default patterns
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // Default masking patterns for each PHI type
        patterns.insert(PhiFieldType::Name, MaskingPattern::PartialMask { prefix: 1, suffix: 0 });
        patterns.insert(PhiFieldType::Ssn, MaskingPattern::PartialMask { prefix: 0, suffix: 4 });
        patterns.insert(PhiFieldType::Mrn, MaskingPattern::Hash);
        patterns.insert(PhiFieldType::DateOfBirth, MaskingPattern::DateGeneralize);
        patterns.insert(PhiFieldType::Address, MaskingPattern::Asterisk);
        patterns.insert(PhiFieldType::PhoneNumber, MaskingPattern::PartialMask { prefix: 0, suffix: 4 });
        patterns.insert(PhiFieldType::Email, MaskingPattern::PartialMask { prefix: 2, suffix: 0 });
        patterns.insert(PhiFieldType::InsuranceId, MaskingPattern::Hash);
        patterns.insert(PhiFieldType::GenericId, MaskingPattern::Hash);

        Self {
            patterns,
            deterministic: false,
            salt: Vec::new(),
        }
    }

    /// Create a deterministic masking engine (same input always produces same output)
    pub fn deterministic(salt: &[u8]) -> Self {
        let mut engine = Self::new();
        engine.deterministic = true;
        engine.salt = salt.to_vec();
        engine
    }

    /// Set a custom masking pattern for a field type
    pub fn set_pattern(&mut self, field_type: PhiFieldType, pattern: MaskingPattern) {
        self.patterns.insert(field_type, pattern);
    }

    /// Mask a PHI value according to its field type
    pub fn mask(&self, field_type: PhiFieldType, value: &str) -> String {
        let pattern = self.patterns.get(&field_type);

        match pattern {
            Some(MaskingPattern::Asterisk) => "*".repeat(value.len()),
            Some(MaskingPattern::XMask) => "X".repeat(value.len()),
            Some(MaskingPattern::PartialMask { prefix, suffix }) => {
                let len = value.len();
                if len <= *prefix + *suffix {
                    return "*".repeat(len);
                }
                let prefix_str: String = value.chars().take(*prefix).collect();
                let suffix_str: String = value.chars().skip(len.saturating_sub(*suffix)).collect();
                let middle_len = len.saturating_sub(*prefix).saturating_sub(*suffix);
                format!("{}{}{}",prefix_str, "*".repeat(middle_len), suffix_str)
            }
            Some(MaskingPattern::Hash) => {
                // Simple hash representation (in production, use proper cryptographic hash)
                if self.deterministic {
                    format!("HASH_{:08x}", self.simple_hash(value))
                } else {
                    format!("HASH_{:08x}", rand::random::<u32>())
                }
            }
            Some(MaskingPattern::Randomize) => {
                // Generate random alphanumeric of same length
                (0..value.len()).map(|_| {
                    let idx = rand::random::<usize>() % 36;
                    if idx < 10 {
                        (b'0' + idx as u8) as char
                    } else {
                        (b'A' + (idx - 10) as u8) as char
                    }
                }).collect()
            }
            Some(MaskingPattern::DateGeneralize) => {
                // Extract just the year if possible, otherwise mask
                if value.len() >= 4 {
                    let year: String = value.chars().take(4).collect();
                    if year.chars().all(|c| c.is_ascii_digit()) {
                        return format!("{}-XX-XX", year);
                    }
                }
                "*".repeat(value.len())
            }
            None => "*".repeat(value.len()),
        }
    }

    /// Simple hash function for deterministic masking
    fn simple_hash(&self, value: &str) -> u32 {
        let mut hash: u32 = 0;
        for byte in self.salt.iter().chain(value.as_bytes().iter()) {
            hash = hash.wrapping_mul(31).wrapping_add(*byte as u32);
        }
        hash
    }

    /// Mask multiple fields at once
    pub fn mask_fields(&self, fields: &[(PhiFieldType, &str)]) -> Vec<String> {
        fields.iter().map(|(ft, val)| self.mask(*ft, val)).collect()
    }

    /// Check if the engine is configured for deterministic masking
    pub fn is_deterministic(&self) -> bool {
        self.deterministic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phi_masking_engine_creation() {
        let engine = PhiMaskingEngine::new();
        assert!(!engine.is_deterministic());
    }

    #[test]
    fn test_ssn_masking() {
        let engine = PhiMaskingEngine::new();
        let masked = engine.mask(PhiFieldType::Ssn, "123-45-6789");
        assert!(masked.ends_with("6789"));
        assert!(masked.contains('*'));
    }

    #[test]
    fn test_name_masking() {
        let engine = PhiMaskingEngine::new();
        let masked = engine.mask(PhiFieldType::Name, "John Doe");
        assert!(masked.starts_with('J'));
        assert!(masked.contains('*'));
    }

    #[test]
    fn test_date_generalization() {
        let engine = PhiMaskingEngine::new();
        let masked = engine.mask(PhiFieldType::DateOfBirth, "1990-01-15");
        assert_eq!(masked, "1990-XX-XX");
    }

    #[test]
    fn test_deterministic_masking() {
        let salt = b"test_salt";
        let engine = PhiMaskingEngine::deterministic(salt);

        let masked1 = engine.mask(PhiFieldType::Mrn, "MRN12345");
        let masked2 = engine.mask(PhiFieldType::Mrn, "MRN12345");

        assert_eq!(masked1, masked2);
        assert!(engine.is_deterministic());
    }

    #[test]
    fn test_asterisk_masking() {
        let mut engine = PhiMaskingEngine::new();
        engine.set_pattern(PhiFieldType::GenericId, MaskingPattern::Asterisk);

        let masked = engine.mask(PhiFieldType::GenericId, "ABC123");
        assert_eq!(masked, "******");
    }

    #[test]
    fn test_batch_masking() {
        let engine = PhiMaskingEngine::new();
        let fields = vec![
            (PhiFieldType::Name, "John Doe"),
            (PhiFieldType::Ssn, "123-45-6789"),
        ];

        let masked = engine.mask_fields(&fields);
        assert_eq!(masked.len(), 2);
    }
}
