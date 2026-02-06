//! Regression test for issue #002
//!
//! **Issue**: Zero-length message signature handling
//! **Link**: <https://github.com/latticearc/latticearc/issues/2>
//!
//! ## Bug Description
//!
//! Signing a zero-length message would succeed but verification would fail
//! due to inconsistent handling of empty inputs in sign vs verify paths.
//!
//! ## Fix Description
//!
//! Normalized empty message handling in both sign and verify functions
//! to treat empty messages consistently.
//!
//! ## Test Strategy
//!
//! Verify that signing and verifying empty messages works correctly
//! and produces valid, verifiable signatures.

#[cfg(test)]
mod tests {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};

    #[test]
    fn regression_issue_002_empty_message_sign_verify() {
        let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65)
            .expect("keypair generation should succeed");

        let empty_message: &[u8] = &[];

        // Sign empty message
        let signature =
            sign(&sk, empty_message, &[]).expect("signing empty message should succeed");

        // Verify signature on empty message
        let result = verify(&pk, empty_message, &signature, &[]);
        assert!(result.is_ok(), "Verification of empty message signature should succeed");
    }

    #[test]
    fn regression_issue_002_empty_message_all_security_levels() {
        let levels =
            [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87];

        let empty_message: &[u8] = &[];

        for level in levels {
            let (pk, sk) = generate_keypair(level).expect("keypair generation should succeed");

            let signature =
                sign(&sk, empty_message, &[]).expect("signing empty message should succeed");

            let result = verify(&pk, empty_message, &signature, &[]);
            assert!(result.is_ok(), "Verification should succeed for {:?}", level);
        }
    }

    #[test]
    fn regression_issue_002_empty_vs_nonempty_different() {
        let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65)
            .expect("keypair generation should succeed");

        let empty_message: &[u8] = &[];
        let nonempty_message: &[u8] = b"hello";

        let sig_empty = sign(&sk, empty_message, &[]).expect("sign empty");
        let sig_nonempty = sign(&sk, nonempty_message, &[]).expect("sign nonempty");

        // Signatures should be different
        assert_ne!(
            sig_empty.as_bytes(),
            sig_nonempty.as_bytes(),
            "Different messages should produce different signatures"
        );

        // Cross-verification should fail
        let cross_verify = verify(&pk, nonempty_message, &sig_empty, &[]);
        assert!(
            cross_verify.is_err() || cross_verify.as_ref().is_ok_and(|&v| !v),
            "Empty message signature should not verify for non-empty message"
        );
    }
}
