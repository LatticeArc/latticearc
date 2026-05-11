#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Composition Security Proofs Module
//!
//! This module provides formal security analysis and proofs for hybrid cryptographic
//! schemes. It demonstrates that the hybrid constructions maintain security properties
//! when combining post-quantum and classical algorithms.
//!
//! # Overview
//!
//! The security of hybrid schemes depends on the composition of their underlying
//! components. This module provides **documentation** for those compositions —
//! it does not perform runtime verification:
//!
//! - Documented IND-CCA2 claims for hybrid KEM, with the
//!   construction-level reasoning that supports them
//! - Documented EUF-CMA claims for hybrid signatures, with the
//!   AND-composition argument
//! - Pointers to the composition theorems each construction relies on
//!
//! The entry points return a [`HybridSecurityProof`] describing the claim;
//! they do not (and cannot) re-derive the underlying lattice / curve hardness
//! results at runtime. Callers that need *actual* validation should consult
//! the formal-verification artefacts (Kani proofs in `latticearc::types`,
//! published cryptanalysis of ML-KEM / ML-DSA / X25519, etc.).
//!
//! # Security Guarantees
//!
//! ## Hybrid KEM Security
//!
//! The hybrid KEM combines ML-KEM (IND-CCA2) with X25519 ECDH (IND-CPA) using
//! **HKDF-SHA256 combination**, not XOR. The two shared secrets are
//! concatenated and passed as IKM to `HKDF-Extract`, then domain-separated via
//! `HKDF-Expand` (see [`kem_hybrid::derive_hybrid_shared_secret`]). HKDF
//! behaves as a dual-PRF: if either input component remains pseudorandom, the
//! extracted secret is pseudorandom, preserving IND-CCA2 under the HKDF/HMAC
//! PRF assumption. This is the "dual-PRF combiner" construction analysed in
//! Bindel et al., "Hybrid Key Encapsulation Mechanisms and Authenticated Key
//! Exchange" (PQCrypto 2019).
//!
//! ## Hybrid Signature Security
//!
//! The hybrid signature requires both ML-DSA-65 and Ed25519 signatures to
//! verify. This AND-composition means an attacker must forge both signatures
//! to break the hybrid scheme.
//!
//! [`kem_hybrid::derive_hybrid_shared_secret`]: crate::hybrid::kem_hybrid::derive_hybrid_shared_secret
//!
//! # Example
//!
//! ```rust
//! use latticearc::hybrid::compose::{describe_hybrid_kem_security, describe_hybrid_signature_security, HybridSecurityLevel};
//!
//! // Retrieve the documented hybrid KEM security claim
//! let kem_claim = describe_hybrid_kem_security();
//! assert_eq!(kem_claim.security_level, HybridSecurityLevel::PostQuantum);
//!
//! // Retrieve the documented hybrid signature security claim
//! let sig_claim = describe_hybrid_signature_security();
//! assert_eq!(sig_claim.security_level, HybridSecurityLevel::PostQuantum);
//! ```

/// Security levels for composition
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridSecurityLevel {
    /// Classical security (no quantum resistance)
    Classical,
    /// Quantum resistance (quantum computer attacks)
    QuantumResistant,
    /// Post-quantum security (quantum computer and classical)
    PostQuantum,
}

/// Hybrid security proof containing verification results and analysis.
///
/// This structure captures the complete security analysis for a hybrid
/// cryptographic construction, including the achieved security level,
/// a description of the analysis, and detailed proof steps.
#[derive(Debug, Clone)]
pub struct HybridSecurityProof {
    /// The security level achieved by the hybrid construction.
    pub security_level: HybridSecurityLevel,
    /// Human-readable description of the security analysis.
    pub description: String,
    /// Detailed proof steps documenting the security verification.
    pub proof: Vec<String>,
}

/// Documented hybrid KEM security claim.
///
/// Returns the recorded claim that the hybrid KEM maintains quantum
/// resistance when ML-KEM and X25519 ECDH are both secure. The
/// underlying reasoning is:
///
/// - The hybrid KEM combines ML-KEM (IND-CCA2 secure) with classical
///   X25519 ECDH (IND-CPA secure).
/// - Composition theorem: if both components are secure, the hybrid
///   is at least as secure as the stronger of the two.
/// - Quantum resistance is rooted in Module-LWE (ML-KEM); classical
///   security is rooted in CDH (X25519).
/// - The hybrid construction feeds both shared secrets through
///   HKDF-SHA256 as a dual-PRF combiner (Bindel et al., PQCrypto
///   2019). If either input remains pseudorandom, the extracted
///   secret is pseudorandom.
///
/// This function does **not** perform runtime verification — it
/// returns the documented claim. Returning a plain
/// [`HybridSecurityProof`] (not a `Result`) makes that explicit:
/// there is no execution path that could fail.
#[must_use = "the returned HybridSecurityProof documents the construction's security claim"]
pub fn describe_hybrid_kem_security() -> HybridSecurityProof {
    // These are documented security claims about the construction, not runtime proofs.
    // The claims hold by inspection of the code paths in kem_hybrid.rs:
    // - ML-KEM encaps/decaps are used directly without modification
    // - X25519 ECDH is used directly without modification
    // - Both shared secrets are combined via HKDF-SHA256 (dual-PRF combiner)
    let proof_steps = vec![
        "ML-KEM IND-CCA2 claim: ML-KEM (FIPS 203) encaps/decaps are used directly; Module-LWE hardness is preserved.".to_string(),
        "ECDH IND-CPA claim: X25519 key agreement is used directly; CDH hardness is preserved.".to_string(),
        "Composition claim: HKDF-SHA256(ML-KEM_ss || ECDH_ss) is a dual-PRF combiner (Bindel et al., PQCrypto 2019). Security holds if either component secret is pseudorandom.".to_string(),
        "Conclusion: Breaking the hybrid KEM requires breaking BOTH ML-KEM and ECDH simultaneously.".to_string(),
    ];

    HybridSecurityProof {
        security_level: HybridSecurityLevel::PostQuantum,
        description: "Hybrid KEM combines ML-KEM (IND-CCA2, Module-LWE) with X25519 ECDH (IND-CPA, CDH) through HKDF-SHA256 dual-PRF combiner. These are documented security claims, not runtime proofs.".to_string(),
        proof: proof_steps,
    }
}

/// Security claim: ML-KEM IND-CCA2 preservation.
///
/// ML-KEM (FIPS 203) provides IND-CCA2 security based on Module-LWE hardness.
/// The hybrid uses ML-KEM encapsulation/decapsulation directly without modification:
/// - ML-KEM ciphertext is used directly
/// - ML-KEM shared secret is fed to HKDF unmodified, then combined with the
///   ECDH secret via HKDF-Extract
/// - No additional exposure of ML-KEM internal state
///
/// This is a documented claim, not a runtime proof.
const _ML_KEM_IND_CCA2_CLAIM: &str = "ML-KEM IND-CCA2 security is preserved: \
    the hybrid construction uses ML-KEM encaps/decaps directly without modification.";

/// Security claim: ECDH IND-CPA preservation.
///
/// X25519 ECDH provides IND-CPA security under the CDH assumption.
/// The hybrid uses ECDH key agreement directly without modification:
/// - ECDH shared secret is fed to HKDF unmodified and combined with the
///   ML-KEM secret via HKDF-Extract (dual-PRF combiner)
/// - No additional exposure of ECDH internal state
///
/// This is a documented claim, not a runtime proof.
const _ECDH_IND_CPA_CLAIM: &str = "ECDH IND-CPA security is preserved: \
    the hybrid construction uses X25519 key agreement directly without modification.";

/// Documented hybrid signature security claim.
///
/// Returns the recorded claim that the hybrid signature maintains
/// security when ML-DSA and Ed25519 are both secure. The underlying
/// reasoning is:
///
/// - The hybrid signature combines ML-DSA (EUF-CMA secure) with
///   Ed25519 (EUF-CMA secure).
/// - Composition: both signatures must be forged to forge the hybrid
///   signature (AND-verification).
/// - Quantum resistance is rooted in Module-SIS (ML-DSA); classical
///   security is rooted in ECDLP (Ed25519).
///
/// This function does **not** perform runtime verification — it
/// returns the documented claim. Returning a plain
/// [`HybridSecurityProof`] (not a `Result`) makes that explicit:
/// there is no execution path that could fail.
#[must_use = "the returned HybridSecurityProof documents the construction's security claim"]
pub fn describe_hybrid_signature_security() -> HybridSecurityProof {
    // These are documented security claims about the construction, not runtime proofs.
    // The claims hold by inspection of the code paths in sig_hybrid.rs:
    // - ML-DSA sign/verify are used directly without modification
    // - Ed25519 sign/verify are used directly without modification
    // - Both signatures are verified (AND-composition)
    let proof_steps = vec![
        "ML-DSA EUF-CMA claim: ML-DSA (FIPS 204) sign/verify are used directly; Module-SIS hardness is preserved.".to_string(),
        "Ed25519 EUF-CMA claim: Ed25519 sign/verify are used directly; ECDLP hardness is preserved.".to_string(),
        "Composition claim: Hybrid signature is (σ_MLDSA, σ_Ed25519) with AND-verification. Forgery requires breaking both EUF-CMA schemes simultaneously.".to_string(),
        "Conclusion: Breaking the hybrid signature requires breaking BOTH ML-DSA and Ed25519 simultaneously.".to_string(),
    ];

    HybridSecurityProof {
        security_level: HybridSecurityLevel::PostQuantum,
        description: "Hybrid signature combines ML-DSA (EUF-CMA, Module-SIS) with Ed25519 (EUF-CMA, ECDLP) via AND-composition. These are documented security claims, not runtime proofs.".to_string(),
        proof: proof_steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_hybrid_kem_security_returns_post_quantum_claim() {
        let proof = describe_hybrid_kem_security();
        assert_eq!(proof.security_level, HybridSecurityLevel::PostQuantum);
        assert!(!proof.description.is_empty());
        assert!(proof.proof.len() >= 4);

        let proof_text = proof.proof.join(" ");
        assert!(proof_text.contains("ML-KEM IND-CCA2"));
        assert!(proof_text.contains("ECDH IND-CPA"));
        assert!(proof_text.contains("Composition claim"));
    }

    #[test]
    fn test_describe_hybrid_signature_security_returns_post_quantum_claim() {
        let proof = describe_hybrid_signature_security();
        assert_eq!(proof.security_level, HybridSecurityLevel::PostQuantum);
        assert!(!proof.description.is_empty());
        assert!(proof.proof.len() >= 4);

        let proof_text = proof.proof.join(" ");
        assert!(proof_text.contains("ML-DSA EUF-CMA"));
        assert!(proof_text.contains("Ed25519 EUF-CMA"));
        assert!(proof_text.contains("Composition claim"));
    }

    #[test]
    fn test_security_claims_exist_and_are_non_empty_succeeds() {
        // Verify the documented security claims are present and non-empty
        assert!(!_ML_KEM_IND_CCA2_CLAIM.is_empty());
        assert!(!_ECDH_IND_CPA_CLAIM.is_empty());
        assert!(_ML_KEM_IND_CCA2_CLAIM.contains("IND-CCA2"));
        assert!(_ECDH_IND_CPA_CLAIM.contains("IND-CPA"));
    }

    #[test]
    fn test_hybrid_kem_proof_structure_has_non_empty_steps_succeeds() {
        let proof = describe_hybrid_kem_security();
        assert!(!proof.proof.is_empty());
        for step in &proof.proof {
            assert!(!step.is_empty(), "Proof step should not be empty");
            assert!(step.len() > 10, "Proof step should have meaningful content");
        }
    }

    #[test]
    fn test_hybrid_signature_proof_structure_succeeds() {
        let proof = describe_hybrid_signature_security();
        assert!(!proof.proof.is_empty());
        for step in &proof.proof {
            assert!(!step.is_empty(), "Proof step should not be empty");
            assert!(step.len() > 10, "Proof step should have meaningful content");
        }
    }

    #[test]
    fn test_security_level_variants_succeeds() {
        let _classical = HybridSecurityLevel::Classical;
        let _quantum_resistant = HybridSecurityLevel::QuantumResistant;
        let _post_quantum = HybridSecurityLevel::PostQuantum;
    }

    #[test]
    fn test_hybrid_security_proof_clone_succeeds() {
        let proof = describe_hybrid_kem_security();
        let proof_clone = proof.clone();
        assert_eq!(proof.security_level, proof_clone.security_level);
        assert_eq!(proof.description, proof_clone.description);
        assert_eq!(proof.proof, proof_clone.proof);
    }

    #[test]
    fn test_full_hybrid_kem_description_text_succeeds() {
        let proof = describe_hybrid_kem_security();
        let proof_text = proof.proof.join("\n");
        assert!(proof_text.contains("ML-KEM IND-CCA2 claim"));
        assert!(proof_text.contains("ECDH IND-CPA claim"));
        assert!(proof_text.contains("dual-PRF combiner"));
        assert!(proof_text.contains("breaking BOTH"));
    }

    #[test]
    fn test_full_hybrid_signature_description_text_succeeds() {
        let proof = describe_hybrid_signature_security();
        let proof_text = proof.proof.join("\n");
        assert!(proof_text.contains("ML-DSA EUF-CMA claim"));
        assert!(proof_text.contains("Ed25519 EUF-CMA claim"));
        assert!(proof_text.contains("AND-verification"));
        assert!(proof.description.contains("AND-composition"));
    }
}
