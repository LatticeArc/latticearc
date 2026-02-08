//! Zero-Knowledge Proofs Example
//!
//! Demonstrates ZKP primitives through the latticearc facade:
//! - Schnorr proofs: prove knowledge of a discrete log without revealing it
//! - Hash commitments: commit to a value, reveal and verify later
//! - Pedersen commitments: information-theoretically hiding commitments
//!
//! Run with: `cargo run --package latticearc --example zero_knowledge_proofs --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::redundant_clone)]

use latticearc::zkp::{HashCommitment, PedersenCommitment, SchnorrProver, SchnorrVerifier};

fn main() {
    println!("=== LatticeArc: Zero-Knowledge Proofs ===\n");

    // -----------------------------------------------------------------------
    // 1. Schnorr Proof: prove knowledge of secret key
    // -----------------------------------------------------------------------
    println!("--- Schnorr Proof ---");
    let (prover, public_key) = SchnorrProver::new().expect("prover creation failed");
    println!("  Public key: {} bytes (secp256k1)", public_key.len());

    let context = b"authentication-challenge-2026";
    let proof = prover.prove(context).expect("prove failed");
    println!("  Proof commitment: {} bytes", proof.commitment.len());
    println!("  Proof response:   {} bytes", proof.response.len());

    let verifier = SchnorrVerifier::new(public_key);
    let is_valid = verifier.verify(&proof, context).expect("verify failed");
    assert!(is_valid, "Valid Schnorr proof should verify");
    println!("  Verification: VALID");

    // Wrong context should fail
    let wrong_context = b"different-challenge";
    let is_valid = verifier.verify(&proof, wrong_context).expect("verify failed");
    assert!(!is_valid, "Wrong context should fail");
    println!("  Wrong context: correctly rejected");

    // Wrong public key should fail
    let (_other_prover, other_pk) = SchnorrProver::new().expect("prover creation failed");
    let other_verifier = SchnorrVerifier::new(other_pk);
    let is_valid = other_verifier.verify(&proof, context).expect("verify failed");
    assert!(!is_valid, "Wrong key should fail");
    println!("  Wrong key: correctly rejected");

    // -----------------------------------------------------------------------
    // 2. Hash Commitment: commit → reveal → verify
    // -----------------------------------------------------------------------
    println!("\n--- Hash Commitment ---");
    let secret_vote = b"candidate_alice";
    let (commitment, opening) = HashCommitment::commit(secret_vote).expect("commit failed");
    println!("  Commitment:  {:02x?}...", &commitment.commitment[..8]);
    println!("  (secret vote hidden until reveal)");

    // Verify the opening
    let is_valid = commitment.verify(&opening).expect("verify failed");
    assert!(is_valid, "Valid opening should verify");
    println!(
        "  Reveal + Verify: VALID (vote = {:?})",
        std::str::from_utf8(&opening.value).unwrap()
    );

    // Tampered opening should fail
    let mut tampered_opening = opening.clone();
    tampered_opening.value = b"candidate_bob".to_vec();
    let is_valid = commitment.verify(&tampered_opening).expect("verify failed");
    assert!(!is_valid, "Tampered opening should fail");
    println!("  Tampered opening: correctly rejected");

    // -----------------------------------------------------------------------
    // 3. Pedersen Commitment: information-theoretic hiding
    // -----------------------------------------------------------------------
    println!("\n--- Pedersen Commitment ---");
    // Use a small value encoded as 32-byte scalar
    let mut value = [0u8; 32];
    value[31] = 42; // commit to the value 42
    let (commitment, opening) = PedersenCommitment::commit(&value).expect("commit failed");
    println!("  Commitment: {} bytes (compressed point)", commitment.commitment.len());

    let is_valid = commitment.verify(&opening).expect("verify failed");
    assert!(is_valid, "Valid Pedersen opening should verify");
    println!("  Verify: VALID (value = 42)");

    // Different value should fail
    let mut wrong_value = opening.clone();
    wrong_value.value[31] = 43; // different value
    let is_valid = commitment.verify(&wrong_value);
    match is_valid {
        Ok(false) | Err(_) => println!("  Wrong value: correctly rejected"),
        Ok(true) => panic!("Wrong value should not verify"),
    }

    println!("\nAll zero-knowledge proof tests passed!");
}
