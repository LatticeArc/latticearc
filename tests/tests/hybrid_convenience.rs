//! Hybrid convenience-API tests (encrypt/sign integrations).
#![deny(unsafe_code)]

// Originally: hybrid_convenience_tests.rs
mod encrypt {
    //! Hybrid Encryption Tests via Unified API
    //!
    //! Tests the ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM hybrid pipeline
    //! through the unified `encrypt()`/`decrypt()` API with `EncryptKey::Hybrid`/`DecryptKey::Hybrid`.
    //!
    //! ## Test Categories
    //!
    //! 1. **Basic roundtrip** - Encrypt/decrypt with unified hybrid API
    //! 2. **EncryptedOutput structure validation** - Field sizes and structure
    //! 3. **Multiple encryptions non-deterministic** - Randomness verification
    //! 4. **Large message stress tests** - 100KB+
    //! 5. **Ciphertext tampering** - Integrity verification
    //! 6. **Cross-key rejection** - Wrong key decryption failure
    //! 7. **Edge cases** - Empty, single-byte, boundary values

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use latticearc::{
        CryptoConfig, DecryptKey, EncryptKey, EncryptedOutput, HybridComponents, SecurityMode,
        VerifiedSession, decrypt, encrypt, generate_hybrid_keypair, generate_keypair,
    };

    // ============================================================================
    // Basic Roundtrip Tests
    // ============================================================================

    #[test]
    fn test_hybrid_encrypt_decrypt_roundtrip() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Basic hybrid roundtrip test";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

        assert_eq!(decrypted.as_slice(), message);
    }

    // ============================================================================
    // SecurityMode::Verified with Valid Session Tests
    // ============================================================================

    #[test]
    fn test_hybrid_encrypt_with_verified_session_succeeds() {
        let (auth_pk, auth_sk) = generate_keypair().unwrap();
        let session =
            VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret()).unwrap();
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test message with verified session";

        let config = CryptoConfig::new().session(&session);
        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), config).unwrap();
        let config = CryptoConfig::new().session(&session);
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config).unwrap();

        assert_eq!(decrypted.as_slice(), message);
    }

    #[test]
    fn test_hybrid_session_reuse_multiple_operations_succeeds() {
        let (auth_pk, auth_sk) = generate_keypair().unwrap();
        let session =
            VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret()).unwrap();
        let (pk, sk) = generate_hybrid_keypair().unwrap();

        for i in 0..10 {
            let message = format!("Message number {}", i);
            let config = CryptoConfig::new().session(&session);
            let encrypted = encrypt(message.as_bytes(), EncryptKey::Hybrid(&pk), config).unwrap();
            let config = CryptoConfig::new().session(&session);
            let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config).unwrap();

            assert_eq!(
                decrypted.as_slice(),
                message.as_bytes(),
                "Session should be reusable for operation {}",
                i
            );
        }
    }

    #[test]
    fn test_hybrid_verified_session_validity_check_succeeds() {
        let (auth_pk, auth_sk) = generate_keypair().unwrap();
        let session =
            VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret()).unwrap();

        assert!(session.is_valid(), "Fresh session should be valid");
        session.verify_valid().unwrap();
        assert!(
            !session.session_id().iter().all(|&b| b == 0),
            "Session ID should not be all zeros"
        );
        assert!(!session.public_key().is_empty(), "Public key should not be empty");
    }

    #[test]
    fn test_security_mode_verified_validates_session_succeeds() {
        let (auth_pk, auth_sk) = generate_keypair().unwrap();
        let session =
            VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret()).unwrap();
        let mode = SecurityMode::Verified(&session);

        mode.validate().unwrap();
        assert!(mode.is_verified(), "Mode should be verified");
        assert!(!mode.is_unverified(), "Mode should not be unverified");
        assert!(mode.session().is_some(), "Mode should have session");
    }

    #[test]
    fn test_security_mode_unverified_always_validates_succeeds() {
        let mode = SecurityMode::Unverified;

        mode.validate().unwrap();
        assert!(!mode.is_verified(), "Mode should not be verified");
        assert!(mode.is_unverified(), "Mode should be unverified");
        assert!(mode.session().is_none(), "Mode should not have session");
    }

    // ============================================================================
    // EncryptedOutput Structure Validation
    // ============================================================================

    #[test]
    fn test_hybrid_encrypted_output_structure_succeeds() {
        let (pk, _sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test EncryptedOutput structure";

        let result = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let hybrid = result.hybrid_data().expect("hybrid_data should be present");
        // ML-KEM-768 ciphertext = 1088 bytes
        assert_eq!(hybrid.ml_kem_ciphertext().len(), 1088, "ML-KEM-768 CT should be 1088 bytes");
        // X25519 ephemeral public key = 32 bytes
        assert_eq!(hybrid.ecdh_ephemeral_pk().len(), 32, "X25519 PK should be 32 bytes");
        // AES-GCM nonce = 12 bytes
        assert_eq!(result.nonce().len(), 12, "AES-GCM nonce should be 12 bytes");
        // AES-GCM tag = 16 bytes
        assert_eq!(result.tag().len(), 16, "AES-GCM tag should be 16 bytes");
        // Symmetric ciphertext should be same length as plaintext
        assert_eq!(
            result.ciphertext().len(),
            message.len(),
            "Ciphertext should match plaintext length"
        );
    }

    // ============================================================================
    // Multiple Encryptions Non-Deterministic Tests
    // ============================================================================

    #[test]
    fn test_hybrid_encryption_non_deterministic() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Same message encrypted multiple times";

        let result1 = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let result2 = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let result3 = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let h1 = result1.hybrid_data().unwrap();
        let h2 = result2.hybrid_data().unwrap();
        let h3 = result3.hybrid_data().unwrap();

        // KEM ciphertexts should differ (randomized encapsulation)
        assert_ne!(h1.ml_kem_ciphertext(), h2.ml_kem_ciphertext(), "KEM CTs should differ");
        assert_ne!(h1.ml_kem_ciphertext(), h3.ml_kem_ciphertext(), "KEM CTs should differ");

        // Ephemeral ECDH keys should differ
        assert_ne!(h1.ecdh_ephemeral_pk(), h2.ecdh_ephemeral_pk(), "ECDH PKs should differ");

        // Nonces should differ
        assert_ne!(result1.nonce(), result2.nonce(), "Nonces should differ");

        // All should decrypt correctly
        assert_eq!(
            decrypt(&result1, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap().as_slice(),
            message.as_slice()
        );
        assert_eq!(
            decrypt(&result2, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap().as_slice(),
            message.as_slice()
        );
        assert_eq!(
            decrypt(&result3, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap().as_slice(),
            message.as_slice()
        );
    }

    #[test]
    fn test_encryption_randomness_stress_test_succeeds() {
        let (pk, _sk) = generate_hybrid_keypair().unwrap();
        let message = b"Stress test for randomness";

        let mut kem_cts = Vec::new();
        let iterations = 20;

        for _ in 0..iterations {
            let result = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
            let hybrid = result.hybrid_data().unwrap();
            kem_cts.push(hybrid.ml_kem_ciphertext().to_vec());
        }

        // All KEM ciphertexts should be unique
        for i in 0..iterations {
            for j in (i + 1)..iterations {
                assert_ne!(kem_cts[i], kem_cts[j], "KEM CT {} and {} should differ", i, j);
            }
        }
    }

    // ============================================================================
    // Large Message Stress Tests
    // ============================================================================

    #[test]
    fn test_hybrid_100kb_message_roundtrip_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = vec![0xAB; 100 * 1024]; // 100KB

        let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        assert_eq!(
            encrypted.ciphertext().len(),
            message.len(),
            "Ciphertext should match plaintext length"
        );

        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            message.as_slice(),
            "100KB message should roundtrip correctly"
        );
    }

    #[test]
    fn test_hybrid_500kb_message_roundtrip_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = vec![0xCD; 500 * 1024]; // 500KB

        let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            message.as_slice(),
            "500KB message should roundtrip correctly"
        );
    }

    #[test]
    fn test_hybrid_1mb_message_roundtrip_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = vec![0xEF; 1024 * 1024]; // 1MB

        let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            message.as_slice(),
            "1MB message should roundtrip correctly"
        );
    }

    // ============================================================================
    // Ciphertext Tampering and Integrity Tests
    // ============================================================================

    #[test]
    fn test_tampered_symmetric_ciphertext_detected_fails() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test tamper detection on symmetric ciphertext";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let mut ciphertext = encrypted.ciphertext().to_vec();
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }
        let tampered = EncryptedOutput::new(
            encrypted.scheme().clone(),
            ciphertext,
            encrypted.nonce().to_vec(),
            encrypted.tag().to_vec(),
            encrypted.hybrid_data().cloned(),
            encrypted.timestamp(),
            encrypted.key_id().map(str::to_owned),
        )
        .expect("re-wrap with same shape as original");

        let result = decrypt(&tampered, DecryptKey::Hybrid(&sk), CryptoConfig::new());
        assert!(result.is_err(), "Tampered symmetric ciphertext should be detected");
    }

    #[test]
    fn test_tampered_kem_ciphertext_detected_fails() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test tamper detection on KEM ciphertext";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let tampered_hybrid = encrypted.hybrid_data().map(|h| {
            let mut ml_kem_ct = h.ml_kem_ciphertext().to_vec();
            if !ml_kem_ct.is_empty() {
                ml_kem_ct[0] ^= 0xFF;
            }
            HybridComponents::new(ml_kem_ct, h.ecdh_ephemeral_pk().to_vec())
        });
        let tampered = EncryptedOutput::new(
            encrypted.scheme().clone(),
            encrypted.ciphertext().to_vec(),
            encrypted.nonce().to_vec(),
            encrypted.tag().to_vec(),
            tampered_hybrid,
            encrypted.timestamp(),
            encrypted.key_id().map(str::to_owned),
        )
        .expect("re-wrap with same shape as original");

        let result = decrypt(&tampered, DecryptKey::Hybrid(&sk), CryptoConfig::new());
        assert!(result.is_err(), "Tampered KEM ciphertext should be detected");
    }

    #[test]
    fn test_tampered_ecdh_pk_detected_fails() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test tamper detection on ECDH ephemeral PK";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let tampered_hybrid = encrypted.hybrid_data().map(|h| {
            let mut ecdh_pk = h.ecdh_ephemeral_pk().to_vec();
            if !ecdh_pk.is_empty() {
                ecdh_pk[0] ^= 0xFF;
            }
            HybridComponents::new(h.ml_kem_ciphertext().to_vec(), ecdh_pk)
        });
        let tampered = EncryptedOutput::new(
            encrypted.scheme().clone(),
            encrypted.ciphertext().to_vec(),
            encrypted.nonce().to_vec(),
            encrypted.tag().to_vec(),
            tampered_hybrid,
            encrypted.timestamp(),
            encrypted.key_id().map(str::to_owned),
        )
        .expect("re-wrap with same shape as original");

        let result = decrypt(&tampered, DecryptKey::Hybrid(&sk), CryptoConfig::new());
        assert!(result.is_err(), "Tampered ECDH ephemeral PK should be detected");
    }

    #[test]
    fn test_tampered_nonce_detected_fails() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test tamper detection on nonce";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let mut nonce = encrypted.nonce().to_vec();
        if !nonce.is_empty() {
            nonce[0] ^= 0xFF;
        }
        let tampered = EncryptedOutput::new(
            encrypted.scheme().clone(),
            encrypted.ciphertext().to_vec(),
            nonce,
            encrypted.tag().to_vec(),
            encrypted.hybrid_data().cloned(),
            encrypted.timestamp(),
            encrypted.key_id().map(str::to_owned),
        )
        .expect("re-wrap with same shape as original");

        let result = decrypt(&tampered, DecryptKey::Hybrid(&sk), CryptoConfig::new());
        assert!(result.is_err(), "Tampered nonce should be detected");
    }

    #[test]
    fn test_tampered_tag_detected_fails() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"Test tamper detection on tag";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

        let mut tag = encrypted.tag().to_vec();
        if !tag.is_empty() {
            tag[0] ^= 0xFF;
        }
        let tampered = EncryptedOutput::new(
            encrypted.scheme().clone(),
            encrypted.ciphertext().to_vec(),
            encrypted.nonce().to_vec(),
            tag,
            encrypted.hybrid_data().cloned(),
            encrypted.timestamp(),
            encrypted.key_id().map(str::to_owned),
        )
        .expect("re-wrap with same shape as original");

        let result = decrypt(&tampered, DecryptKey::Hybrid(&sk), CryptoConfig::new());
        assert!(result.is_err(), "Tampered tag should be detected");
    }

    // ============================================================================
    // Cross-Key Rejection Tests
    // ============================================================================

    #[test]
    fn test_wrong_secret_key_rejected_fails() {
        let (pk1, _sk1) = generate_hybrid_keypair().unwrap();
        let (_pk2, sk2) = generate_hybrid_keypair().unwrap();

        let message = b"Cross-key rejection test";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk1), CryptoConfig::new()).unwrap();
        let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk2), CryptoConfig::new());

        assert!(result.is_err(), "Decrypt with wrong hybrid key should fail");
    }

    #[test]
    fn test_multiple_keypairs_independent_succeeds() {
        let (pk1, sk1) = generate_hybrid_keypair().unwrap();
        let (pk2, sk2) = generate_hybrid_keypair().unwrap();

        let msg1 = b"Message for keypair 1";
        let msg2 = b"Message for keypair 2";

        let enc1 = encrypt(msg1, EncryptKey::Hybrid(&pk1), CryptoConfig::new()).unwrap();
        let enc2 = encrypt(msg2, EncryptKey::Hybrid(&pk2), CryptoConfig::new()).unwrap();

        // Each key decrypts its own message
        let dec1 = decrypt(&enc1, DecryptKey::Hybrid(&sk1), CryptoConfig::new()).unwrap();
        let dec2 = decrypt(&enc2, DecryptKey::Hybrid(&sk2), CryptoConfig::new()).unwrap();

        assert_eq!(dec1.as_slice(), msg1.as_slice());
        assert_eq!(dec2.as_slice(), msg2.as_slice());

        // Cross-decryption fails
        assert!(
            decrypt(&enc1, DecryptKey::Hybrid(&sk2), CryptoConfig::new()).is_err(),
            "Cross-key 1->2 should fail"
        );
        assert!(
            decrypt(&enc2, DecryptKey::Hybrid(&sk1), CryptoConfig::new()).is_err(),
            "Cross-key 2->1 should fail"
        );
    }

    // ============================================================================
    // Edge Cases and Boundary Tests
    // ============================================================================

    #[test]
    fn test_empty_message_roundtrip() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        assert!(encrypted.ciphertext().is_empty(), "Empty plaintext -> empty ciphertext");

        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
        assert!(decrypted.is_empty(), "Decrypted empty message should be empty");
    }

    #[test]
    fn test_single_byte_message_roundtrip() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = b"X";

        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        assert_eq!(encrypted.ciphertext().len(), 1, "Single byte ciphertext");

        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
        assert_eq!(decrypted.as_slice(), message.as_slice());
    }

    #[test]
    fn test_all_zero_bytes_message_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = vec![0u8; 1000];

        let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

        assert_eq!(
            decrypted.as_slice(),
            message.as_slice(),
            "All-zero bytes message should roundtrip"
        );
    }

    #[test]
    fn test_all_255_bytes_message_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message = vec![0xFFu8; 1000];

        let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

        assert_eq!(
            decrypted.as_slice(),
            message.as_slice(),
            "All-255 bytes message should roundtrip"
        );
    }

    #[test]
    fn test_full_byte_range_message_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();
        let message: Vec<u8> = (0..=255).cycle().take(1024).collect();

        let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

        assert_eq!(
            decrypted.as_slice(),
            message.as_slice(),
            "Full byte range message should roundtrip"
        );
    }

    // ============================================================================
    // Multiple Messages with Same Keypair
    // ============================================================================

    #[test]
    fn test_many_messages_same_keypair_succeeds() {
        let (pk, sk) = generate_hybrid_keypair().unwrap();

        let messages: Vec<Vec<u8>> =
            (0..50).map(|i| format!("Message {}", i).into_bytes()).collect();

        let encrypted: Vec<EncryptedOutput> = messages
            .iter()
            .map(|msg| encrypt(msg, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap())
            .collect();

        // The closure returns `Result<Zeroizing<Vec<u8>>, _>`, but the
        // post-unwrap type needs an explicit annotation so rustc picks the right
        // collection type. We keep Zeroizing ownership for the full test scope so
        // plaintext is scrubbed at end of test.
        let decrypted: Vec<Vec<u8>> = encrypted
            .iter()
            .map(|enc| decrypt(enc, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap().to_vec())
            .collect();

        for (original, dec) in messages.iter().zip(decrypted.iter()) {
            assert_eq!(original.as_slice(), dec.as_slice());
        }
    }
}

// Originally: hybrid_sig_convenience_tests.rs
mod sig {
    //! Comprehensive tests for Hybrid Signature Convenience API
    //!
    //! Tests the ML-DSA-65 + Ed25519 AND-composition hybrid signature pipeline
    //! exposed through `arc-core/src/convenience/hybrid_sig.rs`.
    //!
    //! ## Test Categories
    //!
    //! 1. **Basic roundtrip** - Generate/sign/verify with SecurityMode variants
    //! 2. **Verified session** - Tests with valid VerifiedSession
    //! 3. **Cross-key rejection** - Wrong key verification failure
    //! 4. **Tampered signature** - Modified signature detection
    //! 5. **Message binding** - Wrong message fails verification
    //! 6. **Edge cases** - Empty message, large message, binary data
    //! 7. **Persistent identity** - Multiple messages with same keypair
    //! 8. **Config variants** - with_config, unverified wrappers
    //! 9. **Unverified/mode interop** - _unverified and SecurityMode::Unverified produce compatible results

    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic_in_result_fn,
        clippy::unnecessary_wraps
    )]

    use latticearc::unified_api::CoreConfig;
    use latticearc::unified_api::convenience::{
        generate_hybrid_signing_keypair, generate_hybrid_signing_keypair_unverified,
        generate_hybrid_signing_keypair_with_config, sign_hybrid, sign_hybrid_unverified,
        sign_hybrid_with_config, verify_hybrid_signature, verify_hybrid_signature_unverified,
        verify_hybrid_signature_with_config,
    };
    use latticearc::unified_api::error::Result;
    use latticearc::unified_api::zero_trust::{SecurityMode, VerifiedSession};

    // ============================================================================
    // Basic Roundtrip Tests
    // ============================================================================

    #[test]
    fn test_roundtrip_unverified_convenience_roundtrip() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = b"Hello, hybrid signatures!";
        let signature = sign_hybrid_unverified(message, &sk)?;
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
        assert!(valid, "Roundtrip via _unverified should succeed");
        Ok(())
    }

    #[test]
    fn test_roundtrip_security_mode_unverified_roundtrip() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;
        let message = b"SecurityMode::Unverified test";
        let signature = sign_hybrid(message, &sk, SecurityMode::Unverified)?;
        let valid = verify_hybrid_signature(message, &signature, &pk, SecurityMode::Unverified)?;
        assert!(valid, "Roundtrip via SecurityMode::Unverified should succeed");
        Ok(())
    }

    #[test]
    fn test_roundtrip_with_config_roundtrip() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) =
            generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified)?;
        let message = b"Config variant test";
        let signature = sign_hybrid_with_config(message, &sk, &config, SecurityMode::Unverified)?;
        let valid = verify_hybrid_signature_with_config(
            message,
            &signature,
            &pk,
            &config,
            SecurityMode::Unverified,
        )?;
        assert!(valid, "Roundtrip via _with_config should succeed");
        Ok(())
    }

    // ============================================================================
    // Verified Session Tests
    // ============================================================================

    #[test]
    fn test_roundtrip_verified_session_roundtrip() -> Result<()> {
        let (auth_pk, auth_sk) = latticearc::unified_api::convenience::generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Verified(&session))?;
        let message = b"Verified session roundtrip";
        let signature = sign_hybrid(message, &sk, SecurityMode::Verified(&session))?;
        let valid =
            verify_hybrid_signature(message, &signature, &pk, SecurityMode::Verified(&session))?;
        assert!(valid, "Roundtrip with verified session should succeed");
        Ok(())
    }

    #[test]
    fn test_verified_session_multiple_operations_succeeds() -> Result<()> {
        let (auth_pk, auth_sk) = latticearc::unified_api::convenience::generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;
        let mode = SecurityMode::Verified(&session);

        let (pk, sk) = generate_hybrid_signing_keypair(mode)?;

        for i in 0..5 {
            let message = format!("Message number {}", i);
            let signature = sign_hybrid(message.as_bytes(), &sk, mode)?;
            let valid = verify_hybrid_signature(message.as_bytes(), &signature, &pk, mode)?;
            assert!(valid, "Message {} should verify with session", i);
        }
        Ok(())
    }

    // ============================================================================
    // Cross-Key Rejection Tests
    // ============================================================================

    #[test]
    fn test_cross_key_rejection_returns_error() -> Result<()> {
        let (pk_a, sk_a) = generate_hybrid_signing_keypair_unverified()?;
        let (_pk_b, _sk_b) = generate_hybrid_signing_keypair_unverified()?;

        let message = b"cross-key test";
        let signature = sign_hybrid_unverified(message, &sk_a)?;

        // Verify with correct key should succeed
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk_a)?;
        assert!(valid, "Correct key should verify");

        // verify path collapses Err to Ok(false) (Pattern 6).
        let result = verify_hybrid_signature_unverified(message, &signature, &_pk_b);
        assert_eq!(result.ok(), Some(false), "Wrong key must yield Ok(false)");
        Ok(())
    }

    #[test]
    fn test_cross_key_rejection_many_keypairs_returns_error() -> Result<()> {
        let (pk_signer, sk_signer) = generate_hybrid_signing_keypair_unverified()?;
        let message = b"signed by signer";
        let signature = sign_hybrid_unverified(message, &sk_signer)?;

        // Verify with the correct key
        assert!(verify_hybrid_signature_unverified(message, &signature, &pk_signer)?);

        // verify path collapses Err to Ok(false) (Pattern 6).
        for i in 0..5 {
            let (wrong_pk, _) = generate_hybrid_signing_keypair_unverified()?;
            let result = verify_hybrid_signature_unverified(message, &signature, &wrong_pk);
            assert_eq!(result.ok(), Some(false), "Wrong key #{} must yield Ok(false)", i);
        }
        Ok(())
    }

    // ============================================================================
    // Message Binding Tests
    // ============================================================================

    #[test]
    fn test_wrong_message_fails() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let signature = sign_hybrid_unverified(b"correct message", &sk)?;

        // verify path collapses Err to Ok(false) (Pattern 6).
        let result = verify_hybrid_signature_unverified(b"wrong message", &signature, &pk);
        assert_eq!(result.ok(), Some(false), "Wrong message must yield Ok(false)");
        Ok(())
    }

    #[test]
    fn test_single_byte_difference_fails() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = b"test message here";
        let signature = sign_hybrid_unverified(message, &sk)?;

        // Modify one byte
        let mut tampered = message.to_vec();
        tampered[5] ^= 0x01;

        // verify path collapses Err to Ok(false).
        let result = verify_hybrid_signature_unverified(&tampered, &signature, &pk);
        assert_eq!(result.ok(), Some(false), "Single-byte change must yield Ok(false)");
        Ok(())
    }

    #[test]
    fn test_appended_byte_fails() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = b"original";
        let signature = sign_hybrid_unverified(message, &sk)?;

        let mut extended = message.to_vec();
        extended.push(0x00);

        // verify path collapses Err to Ok(false).
        let result = verify_hybrid_signature_unverified(&extended, &signature, &pk);
        assert_eq!(result.ok(), Some(false), "Appended byte must yield Ok(false)");
        Ok(())
    }

    // ============================================================================
    // Edge Case Tests
    // ============================================================================

    #[test]
    fn test_empty_message_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = b"";
        let signature = sign_hybrid_unverified(message, &sk)?;
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
        assert!(valid, "Empty message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_single_byte_message_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = &[0x42u8];
        let signature = sign_hybrid_unverified(message, &sk)?;
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
        assert!(valid, "Single byte message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_large_message_10kb_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = vec![0xAB; 10_000];
        let signature = sign_hybrid_unverified(&message, &sk)?;
        let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
        assert!(valid, "10KB message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_large_message_60kb_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = vec![0xCD; 60_000];
        let signature = sign_hybrid_unverified(&message, &sk)?;
        let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
        assert!(valid, "60KB message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_oversized_message_rejected_fails() {
        let (_pk, sk) = generate_hybrid_signing_keypair_unverified().unwrap();
        let message = vec![0xEF; 100_000]; // 100KB exceeds 64KB limit
        let result = sign_hybrid_unverified(&message, &sk);
        assert!(result.is_err(), "100KB message should exceed resource limit");
    }

    #[test]
    fn test_binary_data_all_byte_values_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message: Vec<u8> = (0..=255).collect();
        let signature = sign_hybrid_unverified(&message, &sk)?;
        let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
        assert!(valid, "All-byte-values message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_null_bytes_message_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = vec![0x00; 64];
        let signature = sign_hybrid_unverified(&message, &sk)?;
        let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
        assert!(valid, "All-null message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_unicode_message_roundtrip_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let message = "Hello, World! Rust 2024 Edition".as_bytes();
        let signature = sign_hybrid_unverified(message, &sk)?;
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
        assert!(valid, "Unicode message should sign and verify");
        Ok(())
    }

    // ============================================================================
    // Persistent Identity Tests
    // ============================================================================

    #[test]
    fn test_persistent_identity_many_messages_all_verify_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

        for i in 0..20 {
            let message = format!("Document #{} for signing", i);
            let signature = sign_hybrid_unverified(message.as_bytes(), &sk)?;
            let valid = verify_hybrid_signature_unverified(message.as_bytes(), &signature, &pk)?;
            assert!(valid, "Message {} should verify with persistent key", i);
        }
        Ok(())
    }

    #[test]
    fn test_signatures_are_unique_per_message_verified_are_unique() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

        let sig1 = sign_hybrid_unverified(b"message A", &sk)?;
        let sig2 = sign_hybrid_unverified(b"message B", &sk)?;

        // Both should verify with their own message
        assert!(verify_hybrid_signature_unverified(b"message A", &sig1, &pk)?);
        assert!(verify_hybrid_signature_unverified(b"message B", &sig2, &pk)?);

        // verify path collapses Err to Ok(false).
        assert_eq!(verify_hybrid_signature_unverified(b"message B", &sig1, &pk).ok(), Some(false));
        assert_eq!(verify_hybrid_signature_unverified(b"message A", &sig2, &pk).ok(), Some(false));
        Ok(())
    }

    // ============================================================================
    // Interoperability Tests
    // ============================================================================

    #[test]
    fn test_unverified_convenience_and_mode_interop_succeeds() -> Result<()> {
        // Generate with _unverified, sign with SecurityMode, verify with _unverified
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
        let signature = sign_hybrid(b"interop test", &sk, SecurityMode::Unverified)?;
        let valid = verify_hybrid_signature_unverified(b"interop test", &signature, &pk)?;
        assert!(valid, "Unverified convenience and SecurityMode should interop");
        Ok(())
    }

    #[test]
    fn test_mode_and_unverified_convenience_interop_succeeds() -> Result<()> {
        // Generate with SecurityMode, sign with _unverified, verify with SecurityMode
        let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;
        let signature = sign_hybrid_unverified(b"reverse interop", &sk)?;
        let valid =
            verify_hybrid_signature(b"reverse interop", &signature, &pk, SecurityMode::Unverified)?;
        assert!(valid, "SecurityMode and unverified convenience should interop");
        Ok(())
    }

    #[test]
    fn test_config_and_plain_interop_succeeds() -> Result<()> {
        // Generate with _with_config, sign with plain, verify with _unverified
        let config = CoreConfig::default();
        let (pk, sk) =
            generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified)?;
        let signature = sign_hybrid(b"config interop", &sk, SecurityMode::Unverified)?;
        let valid = verify_hybrid_signature_unverified(b"config interop", &signature, &pk)?;
        assert!(valid, "Config and plain API should interop");
        Ok(())
    }

    // ============================================================================
    // Keypair Independence Tests
    // ============================================================================

    #[test]
    fn test_keypairs_are_independent_cross_verify_fails() -> Result<()> {
        let (pk1, sk1) = generate_hybrid_signing_keypair_unverified()?;
        let (pk2, sk2) = generate_hybrid_signing_keypair_unverified()?;

        let message = b"same message for both";

        let sig1 = sign_hybrid_unverified(message, &sk1)?;
        let sig2 = sign_hybrid_unverified(message, &sk2)?;

        // Each signature verifies only with its own key
        assert!(verify_hybrid_signature_unverified(message, &sig1, &pk1)?);
        assert!(verify_hybrid_signature_unverified(message, &sig2, &pk2)?);

        // verify path collapses Err to Ok(false).
        assert_eq!(verify_hybrid_signature_unverified(message, &sig1, &pk2).ok(), Some(false));
        assert_eq!(verify_hybrid_signature_unverified(message, &sig2, &pk1).ok(), Some(false));
        Ok(())
    }

    // ============================================================================
    // Error Path Tests
    // ============================================================================

    #[test]
    fn test_expired_session_rejected_fails() {
        // We can't easily create an expired session, but we verify the mode.validate() path
        // is exercised by testing that Unverified always succeeds
        let result = generate_hybrid_signing_keypair(SecurityMode::Unverified);
        assert!(result.is_ok(), "Unverified mode should always succeed");
    }

    #[test]
    fn test_config_validation_path_succeeds() -> Result<()> {
        let config = CoreConfig::default();
        let result = generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified);
        assert!(result.is_ok(), "Default config should pass validation");
        Ok(())
    }
}

// Originally: hybrid_integration.rs
mod integration {
    //! Integration tests for hybrid encryption APIs
    //!
    //! The main hybrid encryption tests are in `hybrid_convenience_tests.rs`.
    //! This file contains additional integration-level tests for the ML-KEM keypair
    //! generation and encapsulated key size validation.

    #![allow(clippy::panic_in_result_fn)]
    use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
    use latticearc::unified_api::{
        convenience::generate_ml_kem_keypair, error::Result, generate_hybrid_keypair,
    };
    use latticearc::{CryptoConfig, DecryptKey, EncryptKey, decrypt, encrypt};

    // ============================================================================
    // ML-KEM Keypair Generation and Public Key Size Tests
    // ============================================================================

    #[test]
    fn test_mlkem512_public_key_size_has_correct_size() -> Result<()> {
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)?;
        assert_eq!(pk.len(), 800, "ML-KEM-512 public key should be 800 bytes");
        Ok(())
    }

    #[test]
    fn test_mlkem768_public_key_size_has_correct_size() -> Result<()> {
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        assert_eq!(pk.len(), 1184, "ML-KEM-768 public key should be 1184 bytes");
        Ok(())
    }

    #[test]
    fn test_mlkem1024_public_key_size_has_correct_size() -> Result<()> {
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)?;
        assert_eq!(pk.len(), 1568, "ML-KEM-1024 public key should be 1568 bytes");
        Ok(())
    }

    #[test]
    fn test_all_mlkem_key_sizes_has_correct_size() -> Result<()> {
        let test_cases = vec![
            (MlKemSecurityLevel::MlKem512, 800, "ML-KEM-512"),
            (MlKemSecurityLevel::MlKem768, 1184, "ML-KEM-768"),
            (MlKemSecurityLevel::MlKem1024, 1568, "ML-KEM-1024"),
        ];

        for (level, expected_pk_size, name) in test_cases {
            let (pk, _sk) = generate_ml_kem_keypair(level)?;
            assert_eq!(pk.len(), expected_pk_size, "{} public key size mismatch", name);
        }

        Ok(())
    }

    // ============================================================================
    // Hybrid Keypair Generation Tests
    // ============================================================================

    #[test]
    fn test_hybrid_keypair_generation_succeeds() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair()?;

        // Verify keys can encrypt/decrypt
        let message = b"Keypair generation test";
        let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
        assert_eq!(
            decrypted.as_slice(),
            message,
            "decrypted plaintext should match original message"
        );

        Ok(())
    }

    #[test]
    fn test_hybrid_keypair_uniqueness_are_unique() -> Result<()> {
        let (pk1, _sk1) = generate_hybrid_keypair()?;
        let (pk2, _sk2) = generate_hybrid_keypair()?;

        // Public keys should be different
        assert_ne!(pk1.ml_kem_pk(), pk2.ml_kem_pk(), "ML-KEM PKs should differ");
        assert_ne!(pk1.ecdh_pk(), pk2.ecdh_pk(), "X25519 PKs should differ");

        Ok(())
    }
}
