#![deny(unsafe_code)]
#![deny(missing_docs)]

//! SAW (Software Analysis Workbench) cryptographic proof specifications.
//!
//! SAW is designed for verifying C/assembly implementations against specifications.
//! Since the TLS module uses aws-lc-rs (which wraps BoringSSL C code), SAW proofs target
//! the underlying C implementations, not the Rust wrappers.
//!
//! This module provides:
//! - Specification references for verified C functions in aws-lc
//! - Proof status tracking for the crypto primitives used by TLS
//! - Integration point for SAW proof results

/// SAW proof status for a crypto primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStatus {
    /// Proof completed and verified.
    Verified,
    /// Proof in progress.
    InProgress,
    /// Not yet started.
    NotStarted,
    /// Not applicable (pure Rust, no C code to verify).
    NotApplicable,
}

/// A SAW proof specification for a crypto primitive.
#[derive(Debug, Clone)]
pub struct SawSpec {
    /// Name of the primitive being verified.
    pub primitive: String,
    /// Status of the SAW proof.
    pub status: ProofStatus,
    /// Reference to the C function being verified (if applicable).
    pub c_function: Option<String>,
    /// Notes about the proof.
    pub notes: String,
}

/// SAW proof registry tracking verification status of crypto primitives.
pub struct SawProofs {
    /// Proof specifications.
    specs: Vec<SawSpec>,
}

impl SawProofs {
    /// Creates a new SAW proof registry with the primitives used by the TLS module.
    #[must_use]
    pub fn new() -> Self {
        Self {
            specs: vec![
                SawSpec {
                    primitive: "AES-256-GCM".to_string(),
                    status: ProofStatus::Verified,
                    c_function: Some("aes_gcm_encrypt/decrypt".to_string()),
                    notes: "Verified by AWS-LC team via SAW".to_string(),
                },
                SawSpec {
                    primitive: "X25519".to_string(),
                    status: ProofStatus::Verified,
                    c_function: Some("X25519_keypair / X25519".to_string()),
                    notes: "Verified by AWS-LC team via SAW".to_string(),
                },
                SawSpec {
                    primitive: "ML-KEM-768".to_string(),
                    status: ProofStatus::InProgress,
                    c_function: Some("MLKEM768_encapsulate / MLKEM768_decapsulate".to_string()),
                    notes: "NIST PQC; SAW proofs being developed upstream".to_string(),
                },
                SawSpec {
                    primitive: "HKDF-SHA256".to_string(),
                    status: ProofStatus::Verified,
                    c_function: Some("HKDF_extract / HKDF_expand".to_string()),
                    notes: "Verified by AWS-LC team via SAW".to_string(),
                },
                SawSpec {
                    primitive: "TLS 1.3 state machine".to_string(),
                    status: ProofStatus::NotApplicable,
                    c_function: None,
                    notes: "Pure Rust (rustls), not applicable for SAW".to_string(),
                },
            ],
        }
    }

    /// Get all proof specifications.
    #[must_use]
    pub fn specs(&self) -> &[SawSpec] {
        &self.specs
    }

    /// Get proofs with a specific status.
    #[must_use]
    pub fn with_status(&self, status: ProofStatus) -> Vec<&SawSpec> {
        self.specs.iter().filter(|s| s.status == status).collect()
    }

    /// Check if all applicable primitives are verified.
    #[must_use]
    pub fn all_verified(&self) -> bool {
        self.specs
            .iter()
            .all(|s| s.status == ProofStatus::Verified || s.status == ProofStatus::NotApplicable)
    }

    /// Get count of proofs by status.
    #[must_use]
    pub fn summary(&self) -> (usize, usize, usize, usize) {
        let verified = self.specs.iter().filter(|s| s.status == ProofStatus::Verified).count();
        let in_progress = self.specs.iter().filter(|s| s.status == ProofStatus::InProgress).count();
        let not_started = self.specs.iter().filter(|s| s.status == ProofStatus::NotStarted).count();
        let not_applicable =
            self.specs.iter().filter(|s| s.status == ProofStatus::NotApplicable).count();
        (verified, in_progress, not_started, not_applicable)
    }
}

impl Default for SawProofs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_saw_proofs_registry() {
        let proofs = SawProofs::new();
        assert_eq!(proofs.specs().len(), 5);
    }

    #[test]
    fn test_saw_proofs_verified_count() {
        let proofs = SawProofs::new();
        let verified = proofs.with_status(ProofStatus::Verified);
        assert_eq!(verified.len(), 3); // AES-GCM, X25519, HKDF
    }

    #[test]
    fn test_saw_proofs_in_progress() {
        let proofs = SawProofs::new();
        let in_progress = proofs.with_status(ProofStatus::InProgress);
        assert_eq!(in_progress.len(), 1); // ML-KEM
        assert_eq!(in_progress[0].primitive, "ML-KEM-768");
    }

    #[test]
    fn test_saw_proofs_not_applicable() {
        let proofs = SawProofs::new();
        let na = proofs.with_status(ProofStatus::NotApplicable);
        assert_eq!(na.len(), 1); // TLS state machine
    }

    #[test]
    fn test_all_verified_false_due_to_ml_kem() {
        let proofs = SawProofs::new();
        assert!(!proofs.all_verified()); // ML-KEM is InProgress
    }

    #[test]
    fn test_saw_proofs_summary() {
        let proofs = SawProofs::new();
        let (verified, in_progress, not_started, not_applicable) = proofs.summary();
        assert_eq!(verified, 3);
        assert_eq!(in_progress, 1);
        assert_eq!(not_started, 0);
        assert_eq!(not_applicable, 1);
    }

    #[test]
    fn test_proof_status_eq() {
        assert_eq!(ProofStatus::Verified, ProofStatus::Verified);
        assert_ne!(ProofStatus::Verified, ProofStatus::InProgress);
    }

    #[test]
    fn test_saw_spec_debug() {
        let spec = SawSpec {
            primitive: "test".to_string(),
            status: ProofStatus::Verified,
            c_function: Some("fn_test".to_string()),
            notes: "notes".to_string(),
        };
        let debug = format!("{:?}", spec);
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_saw_proofs_default() {
        let proofs = SawProofs::default();
        assert!(!proofs.specs().is_empty());
    }
}
