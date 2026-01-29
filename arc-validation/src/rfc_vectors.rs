//! RFC Test Vectors
//!
//! This module validates LatticeArc's cryptographic implementations against
//! official IETF RFC test vectors for protocol compliance.
//!
//! ## Supported RFCs
//!
//! - RFC 7748: X25519 Elliptic Curve Diffie-Hellman
//! - RFC 8032: Ed25519 Digital Signatures
//! - RFC 8439: ChaCha20-Poly1305 AEAD
//! - RFC 5869: HKDF (HMAC-based Key Derivation Function)

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Test result counters - overflow is impossible with realistic test counts
#![allow(clippy::arithmetic_side_effects)]
// JUSTIFICATION: Test code uses expect() for known-valid test vectors and println! for test output
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
// JUSTIFICATION: Clone needed for test data manipulation
#![allow(clippy::redundant_clone)]

use thiserror::Error;

/// Errors from RFC test vector validation
#[derive(Debug, Error)]
pub enum RfcTestError {
    /// Test vector validation failed
    #[error("RFC test failed: {rfc} - {test_name}: {message}")]
    TestFailed {
        /// RFC number
        rfc: String,
        /// Test name
        test_name: String,
        /// Failure message
        message: String,
    },

    /// Hex decoding error
    #[error("Hex decode error: {0}")]
    HexError(String),
}

/// Result of running RFC tests
#[derive(Debug, Default)]
pub struct RfcTestResults {
    /// Total tests run
    pub total: usize,
    /// Tests passed
    pub passed: usize,
    /// Tests failed
    pub failed: usize,
    /// Failure details
    pub failures: Vec<String>,
}

impl RfcTestResults {
    /// Create new results
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a passed test
    pub fn add_pass(&mut self) {
        self.total += 1;
        self.passed += 1;
    }

    /// Record a failed test
    pub fn add_failure(&mut self, message: String) {
        self.total += 1;
        self.failed += 1;
        self.failures.push(message);
    }

    /// Check if all tests passed
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // RFC 8439: ChaCha20-Poly1305 Test Vectors
    // ==========================================================================

    /// RFC 8439 Section 2.4.2: ChaCha20 Block Function Test Vector
    #[test]
    fn test_rfc8439_chacha20_block() {
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };

        let mut results = RfcTestResults::new();

        // RFC 8439 Section 2.8.2: Example and Test Vector for AEAD_CHACHA20_POLY1305
        // Key
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .expect("hex decode");
        let key_array: [u8; 32] = key.try_into().expect("key length");

        // Nonce (96-bit)
        let nonce = hex::decode("070000004041424344454647").expect("hex decode");

        // AAD
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").expect("hex decode");

        // Plaintext
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        // Expected ciphertext + tag from RFC 8439
        let expected_ciphertext = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        ).expect("hex decode");

        let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").expect("hex decode");

        let cipher = ChaCha20Poly1305::new(&key_array.into());

        // Encrypt
        let ciphertext_result =
            cipher.encrypt((&nonce[..]).into(), Payload { msg: plaintext, aad: &aad });

        match ciphertext_result {
            Ok(ct) => {
                // ChaCha20Poly1305 appends the 16-byte tag
                if ct.len() == expected_ciphertext.len() + expected_tag.len() {
                    let (ct_part, tag_part) = ct.split_at(expected_ciphertext.len());
                    if ct_part == expected_ciphertext.as_slice()
                        && tag_part == expected_tag.as_slice()
                    {
                        results.add_pass();
                    } else {
                        results.add_failure("RFC 8439: ciphertext or tag mismatch".to_string());
                    }
                } else {
                    results.add_failure(format!(
                        "RFC 8439: unexpected output length {} vs {}",
                        ct.len(),
                        expected_ciphertext.len() + expected_tag.len()
                    ));
                }
            }
            Err(e) => {
                results.add_failure(format!("RFC 8439: encryption failed: {e:?}"));
            }
        }

        // Decrypt and verify
        let mut ct_with_tag = expected_ciphertext.clone();
        ct_with_tag.extend_from_slice(&expected_tag);

        let decrypt_result =
            cipher.decrypt((&nonce[..]).into(), Payload { msg: &ct_with_tag, aad: &aad });

        match decrypt_result {
            Ok(pt) => {
                if pt == plaintext {
                    results.add_pass();
                } else {
                    results.add_failure("RFC 8439: decrypted plaintext mismatch".to_string());
                }
            }
            Err(e) => {
                results.add_failure(format!("RFC 8439: decryption failed: {e:?}"));
            }
        }

        println!("RFC 8439 ChaCha20-Poly1305: {}/{} passed", results.passed, results.total);
        assert!(results.all_passed(), "RFC 8439 failures: {:?}", results.failures);
    }

    // ==========================================================================
    // RFC 8032: Ed25519 Test Vectors
    // ==========================================================================

    /// RFC 8032 Section 7.1: Ed25519 Test Vectors
    #[test]
    fn test_rfc8032_ed25519() {
        use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

        let mut results = RfcTestResults::new();

        // Test Vector 1 (RFC 8032 Section 7.1, TEST 1)
        let secret_key_1 =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .expect("hex");
        let public_key_1 =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .expect("hex");
        let message_1 = b"";
        let signature_1 = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).expect("hex");

        // Test signing
        let sk_bytes: [u8; 32] = secret_key_1.try_into().expect("sk length");
        let signing_key = SigningKey::from_bytes(&sk_bytes);

        let computed_sig = signing_key.sign(message_1);
        if computed_sig.to_bytes() == signature_1.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 8032 Test 1: signature mismatch".to_string());
        }

        // Test verification
        let pk_bytes: [u8; 32] = public_key_1.try_into().expect("pk length");
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).expect("valid pk");

        let sig_bytes: [u8; 64] = signature_1.try_into().expect("sig length");
        let signature = Signature::from_bytes(&sig_bytes);

        if verifying_key.verify(message_1, &signature).is_ok() {
            results.add_pass();
        } else {
            results.add_failure("RFC 8032 Test 1: verification failed".to_string());
        }

        // Test Vector 2 (RFC 8032 Section 7.1, TEST 2)
        let secret_key_2 =
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .expect("hex");
        let public_key_2 =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .expect("hex");
        let message_2 = hex::decode("72").expect("hex");
        let signature_2 = hex::decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ).expect("hex");

        let sk_bytes_2: [u8; 32] = secret_key_2.try_into().expect("sk length");
        let signing_key_2 = SigningKey::from_bytes(&sk_bytes_2);

        let computed_sig_2 = signing_key_2.sign(&message_2);
        if computed_sig_2.to_bytes() == signature_2.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 8032 Test 2: signature mismatch".to_string());
        }

        let pk_bytes_2: [u8; 32] = public_key_2.try_into().expect("pk length");
        let verifying_key_2 = VerifyingKey::from_bytes(&pk_bytes_2).expect("valid pk");

        let sig_bytes_2: [u8; 64] = signature_2.try_into().expect("sig length");
        let signature_obj_2 = Signature::from_bytes(&sig_bytes_2);

        if verifying_key_2.verify(&message_2, &signature_obj_2).is_ok() {
            results.add_pass();
        } else {
            results.add_failure("RFC 8032 Test 2: verification failed".to_string());
        }

        // Test Vector 3 (RFC 8032 Section 7.1, TEST 3) - 2-byte message
        let secret_key_3 =
            hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
                .expect("hex");
        let public_key_3 =
            hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .expect("hex");
        let message_3 = hex::decode("af82").expect("hex");
        let signature_3 = hex::decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ).expect("hex");

        let sk_bytes_3: [u8; 32] = secret_key_3.try_into().expect("sk length");
        let signing_key_3 = SigningKey::from_bytes(&sk_bytes_3);

        let computed_sig_3 = signing_key_3.sign(&message_3);
        if computed_sig_3.to_bytes() == signature_3.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 8032 Test 3: signature mismatch".to_string());
        }

        let pk_bytes_3: [u8; 32] = public_key_3.try_into().expect("pk length");
        let verifying_key_3 = VerifyingKey::from_bytes(&pk_bytes_3).expect("valid pk");

        let sig_bytes_3: [u8; 64] = signature_3.try_into().expect("sig length");
        let signature_obj_3 = Signature::from_bytes(&sig_bytes_3);

        if verifying_key_3.verify(&message_3, &signature_obj_3).is_ok() {
            results.add_pass();
        } else {
            results.add_failure("RFC 8032 Test 3: verification failed".to_string());
        }

        println!("RFC 8032 Ed25519: {}/{} passed", results.passed, results.total);
        assert!(results.all_passed(), "RFC 8032 failures: {:?}", results.failures);
    }

    // ==========================================================================
    // RFC 7748: X25519 Test Vectors
    // ==========================================================================

    /// RFC 7748 Section 6.1: X25519 Test Vectors
    #[test]
    fn test_rfc7748_x25519() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut results = RfcTestResults::new();

        // RFC 7748 Section 6.1: First test vector
        // Alice's private key (scalar)
        let alice_private =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .expect("hex");
        // Alice's public key
        let alice_public_expected =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .expect("hex");

        // Bob's private key
        let bob_private =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .expect("hex");
        // Bob's public key
        let bob_public_expected =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .expect("hex");

        // Shared secret
        let shared_secret_expected =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .expect("hex");

        // Test Alice's key derivation
        let alice_sk_bytes: [u8; 32] = alice_private.try_into().expect("sk length");
        let alice_secret = StaticSecret::from(alice_sk_bytes);
        let alice_public = PublicKey::from(&alice_secret);

        if alice_public.as_bytes() == alice_public_expected.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 7748: Alice public key mismatch".to_string());
        }

        // Test Bob's key derivation
        let bob_sk_bytes: [u8; 32] = bob_private.try_into().expect("sk length");
        let bob_secret = StaticSecret::from(bob_sk_bytes);
        let bob_public = PublicKey::from(&bob_secret);

        if bob_public.as_bytes() == bob_public_expected.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 7748: Bob public key mismatch".to_string());
        }

        // Test shared secret (Alice computes with Bob's public key)
        let shared_alice = alice_secret.diffie_hellman(&bob_public);
        if shared_alice.as_bytes() == shared_secret_expected.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 7748: Alice shared secret mismatch".to_string());
        }

        // Test shared secret (Bob computes with Alice's public key)
        let shared_bob = bob_secret.diffie_hellman(&alice_public);
        if shared_bob.as_bytes() == shared_secret_expected.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 7748: Bob shared secret mismatch".to_string());
        }

        // Verify both parties compute the same shared secret
        if shared_alice.as_bytes() == shared_bob.as_bytes() {
            results.add_pass();
        } else {
            results.add_failure("RFC 7748: Shared secrets don't match".to_string());
        }

        println!("RFC 7748 X25519: {}/{} passed", results.passed, results.total);
        assert!(results.all_passed(), "RFC 7748 failures: {:?}", results.failures);
    }

    // ==========================================================================
    // RFC 5869: HKDF Test Vectors
    // ==========================================================================

    /// RFC 5869 Appendix A: HKDF Test Vectors (HMAC-SHA256)
    #[test]
    fn test_rfc5869_hkdf() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut results = RfcTestResults::new();

        // Test Case 1: Basic test case with SHA-256
        let ikm_1 = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("hex");
        let salt_1 = hex::decode("000102030405060708090a0b0c").expect("hex");
        let info_1 = hex::decode("f0f1f2f3f4f5f6f7f8f9").expect("hex");
        let expected_prk_1 =
            hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .expect("hex");
        let expected_okm_1 = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .expect("hex");

        let hk_1 = Hkdf::<Sha256>::new(Some(&salt_1), &ikm_1);

        // Check PRK (internal, but we can verify via extract)
        let (prk_1, _) = Hkdf::<Sha256>::extract(Some(&salt_1), &ikm_1);
        if prk_1.as_slice() == expected_prk_1.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 5869 Test 1: PRK mismatch".to_string());
        }

        // Check OKM
        let mut okm_1 = vec![0u8; 42];
        if hk_1.expand(&info_1, &mut okm_1).is_ok() && okm_1 == expected_okm_1 {
            results.add_pass();
        } else {
            results.add_failure("RFC 5869 Test 1: OKM mismatch".to_string());
        }

        // Test Case 2: Longer inputs/outputs
        let ikm_2 = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        ).expect("hex");
        let salt_2 = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        ).expect("hex");
        let info_2 = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ).expect("hex");
        let expected_prk_2 =
            hex::decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
                .expect("hex");
        let expected_okm_2 = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        ).expect("hex");

        let (prk_2, _) = Hkdf::<Sha256>::extract(Some(&salt_2), &ikm_2);
        if prk_2.as_slice() == expected_prk_2.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 5869 Test 2: PRK mismatch".to_string());
        }

        let hk_2 = Hkdf::<Sha256>::new(Some(&salt_2), &ikm_2);
        let mut okm_2 = vec![0u8; 82];
        if hk_2.expand(&info_2, &mut okm_2).is_ok() && okm_2 == expected_okm_2 {
            results.add_pass();
        } else {
            results.add_failure("RFC 5869 Test 2: OKM mismatch".to_string());
        }

        // Test Case 3: Zero-length salt/info
        let ikm_3 = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").expect("hex");
        let expected_prk_3 =
            hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                .expect("hex");
        let expected_okm_3 = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .expect("hex");

        // No salt (uses default)
        let (prk_3, _) = Hkdf::<Sha256>::extract(None, &ikm_3);
        if prk_3.as_slice() == expected_prk_3.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("RFC 5869 Test 3: PRK mismatch".to_string());
        }

        let hk_3 = Hkdf::<Sha256>::new(None, &ikm_3);
        let mut okm_3 = vec![0u8; 42];
        // Empty info
        if hk_3.expand(&[], &mut okm_3).is_ok() && okm_3 == expected_okm_3 {
            results.add_pass();
        } else {
            results.add_failure("RFC 5869 Test 3: OKM mismatch".to_string());
        }

        println!("RFC 5869 HKDF: {}/{} passed", results.passed, results.total);
        assert!(results.all_passed(), "RFC 5869 failures: {:?}", results.failures);
    }

    // ==========================================================================
    // AES-GCM Test Vectors (NIST SP 800-38D)
    // ==========================================================================

    /// NIST SP 800-38D: AES-GCM Test Vectors
    #[test]
    fn test_nist_aes_gcm() {
        use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let mut results = RfcTestResults::new();

        // Test Case 1: AES-128-GCM (from NIST test vectors)
        let key_128 = hex::decode("00000000000000000000000000000000").expect("hex");
        let nonce_1 = hex::decode("000000000000000000000000").expect("hex");
        let plaintext_1: &[u8] = &[];
        let expected_tag_1 = hex::decode("58e2fccefa7e3061367f1d57a4e7455a").expect("hex");

        let unbound_key_1 = UnboundKey::new(&AES_128_GCM, &key_128).expect("key");
        let key_1 = LessSafeKey::new(unbound_key_1);
        let nonce_array_1: [u8; 12] = nonce_1.try_into().expect("nonce");
        let nonce_obj_1 = Nonce::assume_unique_for_key(nonce_array_1);

        let mut in_out_1 = plaintext_1.to_vec();
        let result_1 = key_1.seal_in_place_append_tag(nonce_obj_1, Aad::empty(), &mut in_out_1);

        if let Ok(()) = result_1 {
            // For empty plaintext, output is just the tag
            if in_out_1 == expected_tag_1 {
                results.add_pass();
            } else {
                results.add_failure(format!(
                    "NIST AES-128-GCM Test 1: tag mismatch, got {:?}",
                    hex::encode(&in_out_1)
                ));
            }
        } else {
            results.add_failure("NIST AES-128-GCM Test 1: encryption failed".to_string());
        }

        // Test Case 2: AES-256-GCM with plaintext
        let key_256 =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .expect("hex");
        let nonce_2 = hex::decode("000000000000000000000000").expect("hex");
        let plaintext_2 = hex::decode("00000000000000000000000000000000").expect("hex");
        let expected_ct_2 = hex::decode("cea7403d4d606b6e074ec5d3baf39d18").expect("hex");
        let expected_tag_2 = hex::decode("d0d1c8a799996bf0265b98b5d48ab919").expect("hex");

        let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_256).expect("key");
        let key_2 = LessSafeKey::new(unbound_key_2);
        let nonce_array_2: [u8; 12] = nonce_2.try_into().expect("nonce");
        let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

        let mut in_out_2 = plaintext_2.clone();
        let result_2 = key_2.seal_in_place_append_tag(nonce_obj_2, Aad::empty(), &mut in_out_2);

        if let Ok(()) = result_2 {
            let mut expected_output_2 = expected_ct_2.clone();
            expected_output_2.extend_from_slice(&expected_tag_2);

            if in_out_2 == expected_output_2 {
                results.add_pass();
            } else {
                results.add_failure("NIST AES-256-GCM Test 2: output mismatch".to_string());
            }
        } else {
            results.add_failure("NIST AES-256-GCM Test 2: encryption failed".to_string());
        }

        // Test decryption
        let unbound_key_3 = UnboundKey::new(&AES_256_GCM, &key_256).expect("key");
        let key_3 = LessSafeKey::new(unbound_key_3);
        let nonce_3 = hex::decode("000000000000000000000000").expect("hex");
        let nonce_array_3: [u8; 12] = nonce_3.try_into().expect("nonce");
        let nonce_obj_3 = Nonce::assume_unique_for_key(nonce_array_3);

        let mut ct_with_tag = expected_ct_2.clone();
        ct_with_tag.extend_from_slice(&expected_tag_2);

        let result_3 = key_3.open_in_place(nonce_obj_3, Aad::empty(), &mut ct_with_tag);

        if let Ok(pt) = result_3 {
            if pt == plaintext_2.as_slice() {
                results.add_pass();
            } else {
                results.add_failure(
                    "NIST AES-256-GCM Test 3: decrypted plaintext mismatch".to_string(),
                );
            }
        } else {
            results.add_failure("NIST AES-256-GCM Test 3: decryption failed".to_string());
        }

        println!("NIST AES-GCM: {}/{} passed", results.passed, results.total);
        assert!(results.all_passed(), "NIST AES-GCM failures: {:?}", results.failures);
    }

    /// SHA-256 test vectors from NIST
    #[test]
    fn test_nist_sha256() {
        use sha2::{Digest, Sha256};

        let mut results = RfcTestResults::new();

        // Test vector 1: Empty string
        let expected_1 =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("hex");

        let mut hasher_1 = Sha256::new();
        hasher_1.update(b"");
        let result_1 = hasher_1.finalize();

        if result_1.as_slice() == expected_1.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("NIST SHA-256 Test 1: hash mismatch".to_string());
        }

        // Test vector 2: "abc"
        let expected_2 =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("hex");

        let mut hasher_2 = Sha256::new();
        hasher_2.update(b"abc");
        let result_2 = hasher_2.finalize();

        if result_2.as_slice() == expected_2.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("NIST SHA-256 Test 2: hash mismatch".to_string());
        }

        // Test vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let expected_3 =
            hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
                .expect("hex");

        let mut hasher_3 = Sha256::new();
        hasher_3.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let result_3 = hasher_3.finalize();

        if result_3.as_slice() == expected_3.as_slice() {
            results.add_pass();
        } else {
            results.add_failure("NIST SHA-256 Test 3: hash mismatch".to_string());
        }

        println!("NIST SHA-256: {}/{} passed", results.passed, results.total);
        assert!(results.all_passed(), "NIST SHA-256 failures: {:?}", results.failures);
    }
}
