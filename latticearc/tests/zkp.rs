//! Comprehensive Zero-Knowledge Proof Tests
//!
//! Tests for Schnorr proofs, Pedersen commitments, Hash commitments,
//! and Sigma protocols (DLOG equality).

// ZKP is not FIPS-approved; skip these tests when the `fips` feature is active.
#![cfg(not(feature = "fips"))]
#![allow(clippy::expect_used)]
#![allow(clippy::arithmetic_side_effects)]

use latticearc::zkp::{
    DlogEqualityProof, DlogEqualityStatement, HashCommitment, HashOpening, PedersenCommitment,
    PedersenOpening, SchnorrProof, SchnorrProver, SchnorrVerifier, ZkpError,
};

// ============================================================================
// Schnorr Proof Tests
// ============================================================================

mod schnorr_tests {
    use super::*;

    #[test]
    fn test_schnorr_basic_prove_verify_succeeds() {
        let (prover, public_key) = SchnorrProver::new().expect("prover creation should succeed");
        let proof = prover.prove(b"test context").expect("prove should succeed");

        let verifier = SchnorrVerifier::new(public_key);
        let result = verifier.verify(&proof, b"test context").expect("verify should succeed");

        assert!(result, "Valid proof should verify");
    }

    #[test]
    fn test_schnorr_wrong_context_fails() {
        let (prover, public_key) = SchnorrProver::new().expect("prover creation should succeed");
        let proof = prover.prove(b"context A").expect("prove should succeed");

        let verifier = SchnorrVerifier::new(public_key);
        let result = verifier.verify(&proof, b"context B").expect("verify should return result");

        assert!(!result, "Proof with wrong context should fail");
    }

    #[test]
    fn test_schnorr_empty_context_succeeds() {
        let (prover, public_key) = SchnorrProver::new().expect("prover creation should succeed");
        let proof = prover.prove(b"").expect("prove with empty context should succeed");

        let verifier = SchnorrVerifier::new(public_key);
        let result = verifier.verify(&proof, b"").expect("verify should succeed");

        assert!(result, "Empty context proof should verify");
    }

    #[test]
    fn test_schnorr_large_context_succeeds() {
        let large_context = vec![0xABu8; 10000];

        let (prover, public_key) = SchnorrProver::new().expect("prover creation should succeed");
        let proof = prover.prove(&large_context).expect("prove with large context should succeed");

        let verifier = SchnorrVerifier::new(public_key);
        let result = verifier.verify(&proof, &large_context).expect("verify should succeed");

        assert!(result, "Large context proof should verify");
    }

    #[test]
    fn test_schnorr_multiple_proofs_same_prover_succeeds() {
        let (prover, public_key) = SchnorrProver::new().expect("prover creation should succeed");
        let verifier = SchnorrVerifier::new(public_key);

        for i in 0..5 {
            let context = format!("context {}", i);
            let proof = prover.prove(context.as_bytes()).expect("prove should succeed");
            let result =
                verifier.verify(&proof, context.as_bytes()).expect("verify should succeed");
            assert!(result, "Proof {} should verify", i);
        }
    }

    #[test]
    fn test_schnorr_different_provers_different_keys_succeeds() {
        let (prover1, pk1) = SchnorrProver::new().expect("prover1 creation should succeed");
        let (_prover2, pk2) = SchnorrProver::new().expect("prover2 creation should succeed");

        // Public keys should be different
        assert_ne!(pk1, pk2, "Different provers should have different keys");

        // Proof from prover1 should not verify with pk2
        let proof1 = prover1.prove(b"test").expect("prove should succeed");
        let verifier2 = SchnorrVerifier::new(pk2);
        let result = verifier2.verify(&proof1, b"test").expect("verify should return result");

        assert!(!result, "Proof from different prover should fail");
    }

    #[test]
    fn test_schnorr_proof_uniqueness_are_unique() {
        let (prover, _pk) = SchnorrProver::new().expect("prover creation should succeed");

        let proof1 = prover.prove(b"same context").expect("prove should succeed");
        let proof2 = prover.prove(b"same context").expect("prove should succeed");

        // Proofs should be different due to randomness (different commitments)
        assert_ne!(
            proof1.commitment(),
            proof2.commitment(),
            "Different proofs for same context should have unique commitments"
        );
    }

    #[test]
    fn test_schnorr_from_secret_is_deterministic() {
        let secret = [42u8; 32];
        let (prover1, pk1) =
            SchnorrProver::from_secret(&secret).expect("from_secret should succeed");
        let (_prover2, pk2) =
            SchnorrProver::from_secret(&secret).expect("from_secret should succeed");

        // Same secret should produce same public key
        assert_eq!(pk1, pk2, "Same secret should produce same public key");

        // Proofs should still verify
        let proof = prover1.prove(b"test").expect("prove should succeed");
        let verifier = SchnorrVerifier::new(pk1);
        assert!(verifier.verify(&proof, b"test").expect("verify"), "Proof should verify");
    }

    #[test]
    fn test_schnorr_public_key_accessor_succeeds() {
        let (prover, pk) = SchnorrProver::new().expect("prover creation should succeed");
        assert_eq!(prover.public_key(), &pk, "public_key() should return the same key");
    }
}

// ============================================================================
// Hash Commitment Tests
// ============================================================================

mod hash_commitment_tests {
    use super::*;

    #[test]
    fn test_hash_commitment_basic_succeeds() {
        let message = b"secret message";
        let (commitment, opening) = HashCommitment::commit(message).expect("commit should succeed");

        let result = commitment.verify(&opening).expect("verify should succeed");
        assert!(result, "Valid commitment should verify");
    }

    #[test]
    fn test_hash_commitment_wrong_opening_fails() {
        let message1 = b"message 1";
        let message2 = b"message 2";

        let (commitment1, _opening1) =
            HashCommitment::commit(message1).expect("commit should succeed");
        let (_commitment2, opening2) =
            HashCommitment::commit(message2).expect("commit should succeed");

        let result = commitment1.verify(&opening2).expect("verify should return result");
        assert!(!result, "Wrong opening should fail");
    }

    #[test]
    fn test_hash_commitment_empty_message_succeeds() {
        let message = b"";
        let (commitment, opening) = HashCommitment::commit(message).expect("commit should succeed");

        let result = commitment.verify(&opening).expect("verify should succeed");
        assert!(result, "Empty message commitment should verify");
    }

    #[test]
    fn test_hash_commitment_large_message_succeeds() {
        let message = vec![0xFFu8; 100000];
        let (commitment, opening) =
            HashCommitment::commit(&message).expect("commit should succeed");

        let result = commitment.verify(&opening).expect("verify should succeed");
        assert!(result, "Large message commitment should verify");
    }

    #[test]
    fn test_hash_commitment_hiding_succeeds() {
        let message = b"secret";

        let (commitment1, _) = HashCommitment::commit(message).expect("commit should succeed");
        let (commitment2, _) = HashCommitment::commit(message).expect("commit should succeed");

        // Due to randomness, commitments to same message should be different
        assert_ne!(
            commitment1.commitment(),
            commitment2.commitment(),
            "Commitments should be hiding (different for same message)"
        );
    }

    #[test]
    fn test_hash_commitment_deterministic_with_randomness_is_deterministic() {
        let message = b"test";
        let randomness = [42u8; 32];

        let c1 = HashCommitment::commit_with_randomness(message, randomness).unwrap();
        let c2 = HashCommitment::commit_with_randomness(message, randomness).unwrap();

        assert_eq!(
            c1.commitment(),
            c2.commitment(),
            "Same randomness should produce same commitment"
        );
    }

    #[test]
    fn test_hash_commitment_modified_value_fails() {
        let message = b"original";
        let (commitment, opening) = HashCommitment::commit(message).expect("commit should succeed");

        // Modify the value in the opening by constructing a new one with different value
        let modified_opening = HashOpening::new(b"modified".to_vec(), *opening.randomness());

        let result = commitment.verify(&modified_opening).expect("verify should return result");
        assert!(!result, "Modified value should fail verification");
    }

    #[test]
    fn test_hash_commitment_modified_randomness_fails() {
        let message = b"test";
        let (commitment, opening) = HashCommitment::commit(message).expect("commit should succeed");

        // Create new opening with different randomness
        let mut new_randomness = *opening.randomness();
        new_randomness[0] ^= 0xFF;
        let wrong_opening = HashOpening::new(opening.value().to_vec(), new_randomness);

        let result = commitment.verify(&wrong_opening).expect("verify should return result");
        assert!(!result, "Wrong randomness should fail verification");
    }
}

// ============================================================================
// Pedersen Commitment Tests
// ============================================================================

mod pedersen_commitment_tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment_basic_succeeds() {
        let value: [u8; 32] = [1u8; 32];
        let (commitment, opening) =
            PedersenCommitment::commit(&value).expect("commit should succeed");

        let result = commitment.verify(&opening).expect("verify should succeed");
        assert!(result, "Valid Pedersen commitment should verify");
    }

    #[test]
    fn test_pedersen_commitment_zero_value_rejected() {
        // Committing to value = 0 collapses C = v*G + r*H to C = r*H,
        // which exposes the auxiliary generator's blinding share.
        // `commit()` draws blinding from a CSPRNG, so the blinding is
        // non-zero with overwhelming probability — only the zero value
        // input must trigger the rejection.
        let value: [u8; 32] = [0u8; 32];
        assert!(matches!(PedersenCommitment::commit(&value), Err(ZkpError::InvalidScalar)));
    }

    #[test]
    fn test_pedersen_commitment_large_value_succeeds() {
        // Use a large but valid scalar (not all 0xFF which exceeds curve order)
        let mut value: [u8; 32] = [0xFEu8; 32];
        value[31] = 0x00; // Ensure it's within curve order
        let (commitment, opening) =
            PedersenCommitment::commit(&value).expect("commit should succeed");

        let result = commitment.verify(&opening).expect("verify should succeed");
        assert!(result, "Large value commitment should verify");
    }

    #[test]
    fn test_pedersen_commitment_wrong_value_fails() {
        let value: [u8; 32] = [1u8; 32];
        let (commitment, opening) =
            PedersenCommitment::commit(&value).expect("commit should succeed");

        // Create opening with wrong value
        let wrong_opening = PedersenOpening::new([2u8; 32], *opening.blinding());

        let result = commitment.verify(&wrong_opening).expect("verify should return result");
        assert!(!result, "Wrong value should fail verification");
    }

    #[test]
    fn test_pedersen_commitment_wrong_blinding_fails() {
        let value: [u8; 32] = [1u8; 32];
        let (commitment, opening) =
            PedersenCommitment::commit(&value).expect("commit should succeed");

        // Create opening with wrong blinding factor
        let mut wrong_blinding = *opening.blinding();
        wrong_blinding[0] ^= 0xFF;
        let wrong_opening = PedersenOpening::new(*opening.value(), wrong_blinding);

        let result = commitment.verify(&wrong_opening).expect("verify should return result");
        assert!(!result, "Wrong blinding factor should fail verification");
    }

    #[test]
    fn test_pedersen_commitment_hiding_succeeds() {
        let value: [u8; 32] = [42u8; 32];

        let (c1, _) = PedersenCommitment::commit(&value).expect("commit should succeed");
        let (c2, _) = PedersenCommitment::commit(&value).expect("commit should succeed");

        assert_ne!(c1.commitment(), c2.commitment(), "Pedersen commitments should be hiding");
    }

    #[test]
    fn test_pedersen_commitment_deterministic_with_blinding_is_deterministic() {
        let value: [u8; 32] = [1u8; 32];
        let blinding: [u8; 32] = [10u8; 32];

        let (c1, _) = PedersenCommitment::commit_with_blinding(&value, &blinding)
            .expect("commit should succeed");
        let (c2, _) = PedersenCommitment::commit_with_blinding(&value, &blinding)
            .expect("commit should succeed");

        assert_eq!(
            c1.commitment(),
            c2.commitment(),
            "Same blinding should produce same commitment"
        );
    }

    #[test]
    fn test_pedersen_commitment_homomorphic_addition_succeeds() {
        let v1: [u8; 32] = [1u8; 32];
        let v2: [u8; 32] = [2u8; 32];
        let b1: [u8; 32] = [10u8; 32];
        let b2: [u8; 32] = [20u8; 32];

        let (c1, _) =
            PedersenCommitment::commit_with_blinding(&v1, &b1).expect("commit should succeed");
        let (c2, _) =
            PedersenCommitment::commit_with_blinding(&v2, &b2).expect("commit should succeed");

        // Add commitments homomorphically
        let c_sum = c1.add(&c2).expect("add should succeed");

        // Verify the sum is a valid commitment
        assert_eq!(c_sum.commitment().len(), 33, "Sum commitment should be 33 bytes");
    }

    /// Pedersen commit determinism + wire-format check (an earlier audit
    /// rename of the round-10b `*_kat_byte_stable` test).
    ///
    /// This is **not** a Known-Answer Test — a true KAT would pin the
    /// 33-byte SEC1 commitment against an external reference vector
    /// (e.g. an RFC 9381 / VRF KAT or a hand-computed value over the
    /// documented `H` generator). The previous name overpromised; the
    /// implementation only verifies (a) determinism, (b) self-
    /// consistency of the open path, and (c) wire-format stability.
    /// A real KAT is held back until the `H`-generator derivation is
    /// documented in `docs/SECRET_TYPE_INVARIANTS.md`.
    #[test]
    fn test_pedersen_commit_determinism_and_format() {
        let value = [0x01u8; 32];
        let blinding = [0x02u8; 32];

        let (c, opening) = PedersenCommitment::commit_with_blinding(&value, &blinding)
            .expect("KAT: commit must succeed for non-zero scalars");

        // Self-consistency: the produced commitment must verify against
        // its own opening on this exact build.
        assert!(c.verify(&opening).expect("KAT: verify must not error"));

        // Determinism: same inputs MUST produce the same output bytes
        // (Pedersen commit_with_blinding is by construction
        // deterministic in `(value, blinding)`).
        let (c2, _) = PedersenCommitment::commit_with_blinding(&value, &blinding)
            .expect("KAT: re-commit must succeed");
        assert_eq!(
            c.commitment(),
            c2.commitment(),
            "Pedersen commit_with_blinding must be deterministic"
        );

        // Sanity: SEC1-compressed encoding is exactly 33 bytes (1-byte
        // tag + 32-byte x-coordinate). This locks the wire format.
        assert_eq!(c.commitment().len(), 33);
        let tag = c.commitment()[0];
        assert!(
            tag == 0x02 || tag == 0x03,
            "SEC1-compressed prefix MUST be 0x02 or 0x03, got 0x{tag:02x}"
        );
    }

    #[test]
    fn test_pedersen_commit_with_blinding_rejects_zero_scalars() {
        // Zero blinding collapses C = v*G + r*H to C = v*G (loss of
        // hiding). Zero value collapses to C = r*H (exposes blinding
        // share). Both must be refused.
        let zero = [0u8; 32];
        let nonzero = [1u8; 32];

        assert!(matches!(
            PedersenCommitment::commit_with_blinding(&nonzero, &zero),
            Err(ZkpError::InvalidScalar)
        ));
        assert!(matches!(
            PedersenCommitment::commit_with_blinding(&zero, &nonzero),
            Err(ZkpError::InvalidScalar)
        ));
        assert!(matches!(
            PedersenCommitment::commit_with_blinding(&zero, &zero),
            Err(ZkpError::InvalidScalar)
        ));

        // Sanity: non-zero on both sides still succeeds.
        assert!(PedersenCommitment::commit_with_blinding(&nonzero, &nonzero).is_ok());
    }
}

// ============================================================================
// DLOG Equality Proof Tests
// ============================================================================

mod dlog_equality_tests {
    use super::*;
    use k256::{
        FieldBytes, ProjectivePoint, Scalar, SecretKey,
        elliptic_curve::{PrimeField, group::GroupEncoding},
    };

    fn create_dlog_statement(secret: &[u8; 32]) -> (DlogEqualityStatement, [u8; 32]) {
        let x_scalar: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(secret)).into();
        let x_scalar = x_scalar.expect("valid scalar");

        // Two different generators
        let g = ProjectivePoint::GENERATOR;
        let h = PedersenCommitment::generator_h().unwrap();

        // Compute P = x*G and Q = x*H
        let p = g * x_scalar;
        let q = h * x_scalar;

        let g_bytes: [u8; 33] =
            <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).expect("g serialization");
        let h_bytes: [u8; 33] =
            <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).expect("h serialization");
        let p_bytes: [u8; 33] =
            <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).expect("p serialization");
        let q_bytes: [u8; 33] =
            <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).expect("q serialization");

        let statement = DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };

        (statement, *secret)
    }

    #[test]
    fn test_dlog_equality_basic_succeeds() {
        let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret: [u8; 32] = secret_key.to_bytes().into();

        let (statement, secret) = create_dlog_statement(&secret);
        let proof =
            DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove should succeed");

        let result = proof.verify(&statement, b"test").expect("verify should succeed");
        assert!(result, "Valid DLOG equality proof should verify");
    }

    #[test]
    fn test_dlog_equality_wrong_context_fails() {
        let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret: [u8; 32] = secret_key.to_bytes().into();

        let (statement, secret) = create_dlog_statement(&secret);
        let proof = DlogEqualityProof::prove(&statement, &secret, b"context1")
            .expect("prove should succeed");

        let result = proof.verify(&statement, b"context2").expect("verify should return result");
        assert!(!result, "Wrong context should fail verification");
    }

    #[test]
    fn test_dlog_equality_empty_context_succeeds() {
        let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret: [u8; 32] = secret_key.to_bytes().into();

        let (statement, secret) = create_dlog_statement(&secret);
        let proof =
            DlogEqualityProof::prove(&statement, &secret, b"").expect("prove should succeed");

        let result = proof.verify(&statement, b"").expect("verify should succeed");
        assert!(result, "Empty context proof should verify");
    }

    #[test]
    fn test_dlog_equality_large_context_succeeds() {
        let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret: [u8; 32] = secret_key.to_bytes().into();
        let large_context = vec![0xABu8; 10000];

        let (statement, secret) = create_dlog_statement(&secret);
        let proof = DlogEqualityProof::prove(&statement, &secret, &large_context)
            .expect("prove should succeed");

        let result = proof.verify(&statement, &large_context).expect("verify should succeed");
        assert!(result, "Large context proof should verify");
    }

    #[test]
    fn test_dlog_equality_wrong_secret_fails() {
        let secret1 = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret2 = SecretKey::random(&mut rand_core_0_6::OsRng);

        let s1: [u8; 32] = secret1.to_bytes().into();
        let s2: [u8; 32] = secret2.to_bytes().into();

        // Create statement with secret1
        let (statement, _) = create_dlog_statement(&s1);

        // Try to prove with secret2
        let proof =
            DlogEqualityProof::prove(&statement, &s2, b"test").expect("prove should succeed");

        let result = proof.verify(&statement, b"test").expect("verify should return result");
        assert!(!result, "Wrong secret should fail verification");
    }

    #[test]
    fn test_dlog_equality_proof_uniqueness_are_unique() {
        let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret: [u8; 32] = secret_key.to_bytes().into();

        let (statement, secret) = create_dlog_statement(&secret);

        let proof1 =
            DlogEqualityProof::prove(&statement, &secret, b"same").expect("prove should succeed");
        let proof2 =
            DlogEqualityProof::prove(&statement, &secret, b"same").expect("prove should succeed");

        // Proofs should be different due to randomness
        assert_ne!(proof1.a(), proof2.a(), "Proofs should have different commitments");
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_schnorr_and_hash_commitment_together_succeeds() {
        // Commit to a message
        let message = b"my secret message";
        let (commitment, _opening) =
            HashCommitment::commit(message).expect("commit should succeed");

        // Create Schnorr proof using commitment as context
        let (prover, pk) = SchnorrProver::new().expect("prover should succeed");
        let proof = prover.prove(commitment.commitment()).expect("prove should succeed");

        let verifier = SchnorrVerifier::new(pk);
        assert!(
            verifier.verify(&proof, commitment.commitment()).expect("verify"),
            "Proof with commitment as context should verify"
        );
    }

    #[test]
    fn test_concurrent_schnorr_proofs_succeeds() {
        use std::thread;

        let handles: Vec<_> = (0..4)
            .map(|i| {
                thread::spawn(move || {
                    let (prover, pk) = SchnorrProver::new().expect("prover should succeed");
                    let context = format!("thread {}", i);
                    let proof = prover.prove(context.as_bytes()).expect("prove should succeed");

                    let verifier = SchnorrVerifier::new(pk);
                    verifier.verify(&proof, context.as_bytes()).expect("verify should succeed")
                })
            })
            .collect();

        for handle in handles {
            let result = handle.join().expect("thread should not panic");
            assert!(result, "All concurrent proofs should verify");
        }
    }

    #[test]
    fn test_concurrent_hash_commitments_succeeds() {
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::thread;

        let results = Arc::new(Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let results = Arc::clone(&results);
                thread::spawn(move || {
                    let message = format!("message {}", i);
                    let (commitment, opening) =
                        HashCommitment::commit(message.as_bytes()).expect("commit should succeed");
                    let verified = commitment.verify(&opening).expect("verify should succeed");
                    results.lock().expect("lock").push(verified);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let results = results.lock().expect("lock");
        assert!(results.iter().all(|&v| v), "All concurrent commitments should verify");
    }

    #[test]
    fn test_concurrent_pedersen_commitments_succeeds() {
        use std::thread;

        // Iterate from 1 so that no thread tries to commit to value = 0
        // (rejected by `commit_with_blinding`'s zero-scalar guard).
        let handles: Vec<_> = (1..=4u8)
            .map(|i| {
                thread::spawn(move || {
                    let mut value = [0u8; 32];
                    value[0] = i;
                    let (commitment, opening) =
                        PedersenCommitment::commit(&value).expect("commit should succeed");
                    commitment.verify(&opening).expect("verify should succeed")
                })
            })
            .collect();

        for handle in handles {
            let result = handle.join().expect("thread should not panic");
            assert!(result, "All concurrent Pedersen commitments should verify");
        }
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_tests {
    use super::*;

    #[test]
    fn test_invalid_pedersen_scalar_fails() {
        // All 0xFF bytes is not a valid secp256k1 scalar (too large)
        let invalid_value = [0xFFu8; 32];
        let blinding = [1u8; 32];

        let result = PedersenCommitment::commit_with_blinding(&invalid_value, &blinding);
        assert!(result.is_err(), "Invalid scalar should return error");
    }

    #[test]
    fn test_schnorr_corrupted_proof_commitment_fails() {
        let (prover, pk) = SchnorrProver::new().expect("prover should succeed");
        let proof = prover.prove(b"test").expect("prove should succeed");

        // Corrupt the commitment
        let mut corrupted_commitment = *proof.commitment();
        corrupted_commitment[0] ^= 0xFF;
        let corrupted_proof = SchnorrProof::new(corrupted_commitment, *proof.response());

        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&corrupted_proof, b"test");

        // Should either error or return false
        if let Ok(valid) = result {
            assert!(!valid, "Corrupted proof should not verify");
        }
    }

    #[test]
    fn test_schnorr_corrupted_proof_response_fails() {
        let (prover, pk) = SchnorrProver::new().expect("prover should succeed");
        let proof = prover.prove(b"test").expect("prove should succeed");

        // Corrupt the response
        let mut corrupted_response = *proof.response();
        corrupted_response[0] ^= 0xFF;
        let corrupted_proof = SchnorrProof::new(*proof.commitment(), corrupted_response);

        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&corrupted_proof, b"test");

        // Should either error or return false
        if let Ok(valid) = result {
            assert!(!valid, "Corrupted response should not verify");
        }
    }

    // ------------------------------------------------------------------
    // Pattern 14 negative path coverage — an earlier audit follow-up #9.
    //
    // Each test below targets a specific `ZkpError` variant on the
    // `SchnorrVerifier::verify` path, verifying that malformed bytes
    // fail closed rather than spuriously verifying.
    // ------------------------------------------------------------------

    #[test]
    fn test_schnorr_verify_rejects_non_curve_commitment() {
        // 0x04 || 32 zero bytes is a valid uncompressed-prefix shape but
        // the all-zero point is not on secp256k1; `parse_point` returns
        // `ZkpError::InvalidPublicKey`. The verifier must treat this as
        // a hard failure (Result::Err or Ok(false)), not silently accept.
        let (_prover, pk) = SchnorrProver::new().expect("prover should succeed");
        let bad_commitment = [0u8; 33];
        let response = [1u8; 32];
        let bad_proof = SchnorrProof::new(bad_commitment, response);

        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&bad_proof, b"ctx");

        assert!(
            result.is_err() || result.as_ref().is_ok_and(|v| !v),
            "Schnorr verify must reject non-curve commitment, got {result:?}"
        );
    }

    #[test]
    fn test_schnorr_verify_rejects_non_curve_public_key() {
        let (prover, _good_pk) = SchnorrProver::new().expect("prover should succeed");
        let proof = prover.prove(b"ctx").expect("prove should succeed");

        // Public key with a curve-point prefix byte (0x02) but garbage
        // x-coordinate that does not lie on the curve — `parse_point`
        // surfaces `ZkpError::InvalidPublicKey`.
        let mut bad_pk = [0u8; 33];
        bad_pk[0] = 0x02;
        bad_pk[1..].copy_from_slice(&[0xFFu8; 32]);

        let verifier = SchnorrVerifier::new(bad_pk);
        let result = verifier.verify(&proof, b"ctx");

        assert!(
            result.is_err() || result.as_ref().is_ok_and(|v| !v),
            "Schnorr verify must reject non-curve public key, got {result:?}"
        );
    }

    #[test]
    fn test_schnorr_verify_rejects_invalid_compressed_prefix() {
        // First byte of a SEC1-compressed point must be 0x02 or 0x03.
        // Any other value is a parse failure → `ZkpError::InvalidPublicKey`
        // surfaced from `EncodedPoint::from_bytes` (a `SerializationError`
        // wrapped through `parse_point`).
        let (prover, pk) = SchnorrProver::new().expect("prover should succeed");
        let proof = prover.prove(b"ctx").expect("prove should succeed");

        let mut malformed_commitment = *proof.commitment();
        malformed_commitment[0] = 0x05; // invalid SEC1 prefix
        let malformed_proof = SchnorrProof::new(malformed_commitment, *proof.response());

        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&malformed_proof, b"ctx");

        assert!(
            result.is_err() || result.as_ref().is_ok_and(|v| !v),
            "Schnorr verify must reject invalid SEC1 prefix, got {result:?}"
        );
    }
}

// ============================================================================
// Additional Sigma Protocol Tests (for higher coverage)
// ============================================================================

mod sigma_protocol_tests {
    use super::*;
    use k256::{
        FieldBytes, ProjectivePoint, Scalar, SecretKey,
        elliptic_curve::{PrimeField, group::GroupEncoding},
    };

    fn create_valid_statement_and_secret() -> (DlogEqualityStatement, [u8; 32]) {
        let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
        let secret: [u8; 32] = secret_key.to_bytes().into();

        let x_scalar: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(&secret)).into();
        let x_scalar = x_scalar.expect("valid scalar");

        let g = ProjectivePoint::GENERATOR;
        let h = PedersenCommitment::generator_h().unwrap();
        let p = g * x_scalar;
        let q = h * x_scalar;

        let g_bytes: [u8; 33] =
            <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).expect("g");
        let h_bytes: [u8; 33] =
            <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).expect("h");
        let p_bytes: [u8; 33] =
            <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).expect("p");
        let q_bytes: [u8; 33] =
            <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).expect("q");

        (DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes }, secret)
    }

    #[test]
    fn test_dlog_proof_different_generators_succeeds() {
        // the per-multiplier sweep was testing arbitrary
        // h = α·G generators, which now fail prove() because the
        // canonical H is pinned. Replaced with a single iteration
        // over the canonical (G, NUMS H) pair — the loop body is
        // retained to keep the existing assertion structure.
        for multiplier in [2u64] {
            let secret_key = SecretKey::random(&mut rand_core_0_6::OsRng);
            let secret: [u8; 32] = secret_key.to_bytes().into();
            let x_scalar: Option<Scalar> =
                Scalar::from_repr(*FieldBytes::from_slice(&secret)).into();
            let x_scalar = x_scalar.expect("valid scalar");

            let g = ProjectivePoint::GENERATOR;
            let h = PedersenCommitment::generator_h().unwrap();
            let p = g * x_scalar;
            let q = h * x_scalar;

            let g_bytes: [u8; 33] =
                <[u8; 33]>::try_from(g.to_affine().to_bytes().as_slice()).expect("g");
            let h_bytes: [u8; 33] =
                <[u8; 33]>::try_from(h.to_affine().to_bytes().as_slice()).expect("h");
            let p_bytes: [u8; 33] =
                <[u8; 33]>::try_from(p.to_affine().to_bytes().as_slice()).expect("p");
            let q_bytes: [u8; 33] =
                <[u8; 33]>::try_from(q.to_affine().to_bytes().as_slice()).expect("q");

            let statement =
                DlogEqualityStatement { g: g_bytes, h: h_bytes, p: p_bytes, q: q_bytes };
            let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");
            assert!(
                proof.verify(&statement, b"test").expect("verify"),
                "multiplier {}",
                multiplier
            );
        }
    }

    #[test]
    fn test_dlog_proof_corrupted_a_fails() {
        let (statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt commitment A
        let mut corrupted_a = *proof.a();
        corrupted_a[0] ^= 0xFF;
        let corrupted =
            DlogEqualityProof::new(corrupted_a, *proof.b(), *proof.challenge(), *proof.response());

        let result = corrupted.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Corrupted A should fail");
        }
    }

    #[test]
    fn test_dlog_proof_corrupted_b_fails() {
        let (statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt commitment B
        let mut corrupted_b = *proof.b();
        corrupted_b[0] ^= 0xFF;
        let corrupted =
            DlogEqualityProof::new(*proof.a(), corrupted_b, *proof.challenge(), *proof.response());

        let result = corrupted.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Corrupted B should fail");
        }
    }

    #[test]
    fn test_dlog_proof_corrupted_response_fails() {
        let (statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt response
        let mut corrupted_response = *proof.response();
        corrupted_response[0] ^= 0xFF;
        let corrupted =
            DlogEqualityProof::new(*proof.a(), *proof.b(), *proof.challenge(), corrupted_response);

        let result = corrupted.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Corrupted response should fail");
        }
    }

    #[test]
    fn test_dlog_proof_corrupted_challenge_fails() {
        let (statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt challenge
        let mut corrupted_challenge = *proof.challenge();
        corrupted_challenge[0] ^= 0xFF;
        let corrupted =
            DlogEqualityProof::new(*proof.a(), *proof.b(), corrupted_challenge, *proof.response());

        let result = corrupted.verify(&statement, b"test").expect("verify should return result");
        assert!(!result, "Corrupted challenge should fail");
    }

    #[test]
    fn test_dlog_proof_wrong_statement_g_fails() {
        let (mut statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt statement G
        statement.g[0] ^= 0xFF;

        let result = proof.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Wrong G should fail");
        }
    }

    #[test]
    fn test_dlog_proof_wrong_statement_h_fails() {
        let (mut statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt statement H
        statement.h[0] ^= 0xFF;

        let result = proof.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Wrong H should fail");
        }
    }

    #[test]
    fn test_dlog_proof_wrong_statement_p_fails() {
        let (mut statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt statement P
        statement.p[0] ^= 0xFF;

        let result = proof.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Wrong P should fail");
        }
    }

    #[test]
    fn test_dlog_proof_wrong_statement_q_fails() {
        let (mut statement, secret) = create_valid_statement_and_secret();
        let proof = DlogEqualityProof::prove(&statement, &secret, b"test").expect("prove");

        // Corrupt statement Q
        statement.q[0] ^= 0xFF;

        let result = proof.verify(&statement, b"test");
        if let Ok(valid) = result {
            assert!(!valid, "Wrong Q should fail");
        }
    }

    #[test]
    fn test_dlog_proof_multiple_proofs_same_statement_succeeds() {
        let (statement, secret) = create_valid_statement_and_secret();

        // Generate multiple proofs for same statement
        for i in 0..5 {
            let context = format!("proof {}", i);
            let proof =
                DlogEqualityProof::prove(&statement, &secret, context.as_bytes()).expect("prove");
            assert!(
                proof.verify(&statement, context.as_bytes()).expect("verify"),
                "Proof {} should verify",
                i
            );
        }
    }

    #[test]
    fn test_dlog_proof_stress_rapid_generation_succeeds() {
        let (statement, secret) = create_valid_statement_and_secret();

        // Rapid proof generation and verification
        for _ in 0..20 {
            let proof = DlogEqualityProof::prove(&statement, &secret, b"stress").expect("prove");
            assert!(proof.verify(&statement, b"stress").expect("verify"));
        }
    }
}

// ============================================================================
// Property Tests
// ============================================================================

mod property_tests {
    use super::*;

    #[test]
    fn test_schnorr_soundness_succeeds() {
        // Soundness: Cannot forge proof without knowing secret
        let (_prover, pk) = SchnorrProver::new().expect("prover should succeed");
        let (other_prover, _) = SchnorrProver::new().expect("other prover should succeed");

        // other_prover doesn't know prover's secret
        let forged_proof = other_prover.prove(b"test").expect("prove should succeed");

        let verifier = SchnorrVerifier::new(pk);
        let result = verifier.verify(&forged_proof, b"test").expect("verify");

        assert!(!result, "Forged proof should not verify");
    }

    #[test]
    fn test_hash_commitment_binding_succeeds() {
        // Binding: Cannot find two openings for same commitment
        let message = b"original";
        let (commitment, opening) = HashCommitment::commit(message).expect("commit should succeed");

        // Try to create opening with different message but same randomness
        let wrong_opening = HashOpening::new(b"different".to_vec(), *opening.randomness());

        let result = commitment.verify(&wrong_opening).expect("verify");
        assert!(!result, "Different message with same randomness should fail");
    }

    #[test]
    fn test_pedersen_commitment_binding_succeeds() {
        // Binding: Cannot find two openings for same commitment
        let value = [1u8; 32];
        let (commitment, opening) =
            PedersenCommitment::commit(&value).expect("commit should succeed");

        // Try opening with different value
        let wrong_opening = PedersenOpening::new([2u8; 32], *opening.blinding());

        let result = commitment.verify(&wrong_opening).expect("verify");
        assert!(!result, "Different value should fail binding test");
    }
}
