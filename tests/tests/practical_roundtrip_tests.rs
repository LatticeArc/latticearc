//! Practical Round-Trip Integration Tests
//!
//! These tests verify the FULL lifecycle of cryptographic operations as a user
//! would actually use them in production:
//!
//! ```text
//! plaintext → encrypt → serialize → [persist to file] → [read from file]
//!          → deserialize → decrypt → plaintext
//! ```
//!
//! This bridges the gap between:
//! - **Crypto-only tests** (encrypt → decrypt in memory)
//! - **Serialization-only tests** (serialize → deserialize with fake data)
//!
//! Neither of those test paths proves that a REAL encryption output survives
//! the serialize → persist → deserialize → decrypt path.
//!
//! ## Test Categories
//!
//! 1. **Unified API**: encrypt() → serialize → file → deserialize → decrypt()
//! 2. **AES-GCM Direct**: encrypt_aes_gcm() with serialized EncryptedData wrapper
//! 3. **Hybrid Encryption**: encrypt(Hybrid) → serialize components → file → decrypt
//! 4. **Signatures**: sign_with_key() → serialize → file → deserialize → verify()
//! 5. **Key Persistence**: keypair → serialize → file → deserialize → use
//! 6. **Multi-Message**: multiple encrypted messages in one file, selective decrypt
//! 7. **Metadata Inspection**: verify metadata readable without decryption key
//! 8. **Cross-Config**: encrypt with one config, serialize, decrypt with different config
//! 9. **AAD Context Binding**: encrypt_aes_gcm_with_aad round-trip through files
//! 10. **Tamper Detection**: modify serialized data, verify decrypt fails
//!
//! Run with:
//! ```bash
//! cargo test --package latticearc-tests --test practical_roundtrip_tests --all-features --release
//! ```

#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]
use std::collections::HashMap;
use std::io::{Read, Write};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use latticearc::{
    CryptoConfig,
    CryptoScheme,
    // Types
    DecryptKey,
    EncryptKey,
    EncryptedData,
    EncryptedMetadata,
    EncryptedOutput,
    EncryptionScheme,
    HybridComponents,
    SecurityLevel,
    SecurityMode,
    UseCase,
    // Unified API
    decrypt,
    // AES-GCM direct
    decrypt_aes_gcm,
    decrypt_aes_gcm_with_aad,
    // Serialization
    deserialize_encrypted_data,
    deserialize_keypair,
    deserialize_signed_data,
    encrypt,
    encrypt_aes_gcm,
    // AES-GCM with AAD
    encrypt_aes_gcm_with_aad,
    generate_hybrid_keypair,
    // Signing
    generate_signing_keypair,
    serialize_encrypted_data,
    serialize_keypair,
    serialize_signed_data,
    sign_with_key,
    verify,
};

// ============================================================================
// Helpers
// ============================================================================

/// Write string content to a temp file and return it.
fn write_to_tempfile(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(content.as_bytes()).expect("failed to write temp file");
    file.flush().expect("failed to flush temp file");
    file
}

/// Read entire content from a temp file as String.
fn read_from_tempfile(file: &NamedTempFile) -> String {
    let mut content = String::new();
    std::fs::File::open(file.path())
        .expect("failed to open temp file")
        .read_to_string(&mut content)
        .expect("failed to read temp file");
    content
}

/// A JSON-serializable envelope for storing multiple encrypted messages.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedMessageStore {
    version: String,
    messages: Vec<StoredMessage>,
}

/// A single stored message with its label and serialized encrypted data.
#[derive(Debug, Serialize, Deserialize)]
struct StoredMessage {
    label: String,
    encrypted_json: String,
}

/// A JSON-serializable envelope for hybrid encrypted data.
#[derive(Debug, Serialize, Deserialize)]
struct SerializableHybridEncrypted {
    kem_ciphertext: String,       // base64
    ecdh_ephemeral_pk: String,    // base64
    symmetric_ciphertext: String, // base64
    nonce: String,                // base64
    tag: String,                  // base64
}

impl SerializableHybridEncrypted {
    fn from_encrypted_output(output: &EncryptedOutput) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let hybrid = output.hybrid_data.as_ref().expect("hybrid_data must be present");
        Self {
            kem_ciphertext: STANDARD.encode(&hybrid.ml_kem_ciphertext),
            ecdh_ephemeral_pk: STANDARD.encode(&hybrid.ecdh_ephemeral_pk),
            symmetric_ciphertext: STANDARD.encode(&output.ciphertext),
            nonce: STANDARD.encode(&output.nonce),
            tag: STANDARD.encode(&output.tag),
        }
    }

    fn to_encrypted_output(&self) -> EncryptedOutput {
        use base64::{Engine, engine::general_purpose::STANDARD};
        EncryptedOutput {
            scheme: EncryptionScheme::HybridMlKem768Aes256Gcm,
            ciphertext: STANDARD.decode(&self.symmetric_ciphertext).unwrap(),
            nonce: STANDARD.decode(&self.nonce).unwrap(),
            tag: STANDARD.decode(&self.tag).unwrap(),
            hybrid_data: Some(HybridComponents {
                ml_kem_ciphertext: STANDARD.decode(&self.kem_ciphertext).unwrap(),
                ecdh_ephemeral_pk: STANDARD.decode(&self.ecdh_ephemeral_pk).unwrap(),
            }),
            timestamp: chrono::Utc::now().timestamp().unsigned_abs(),
            key_id: None,
        }
    }
}

// ============================================================================
// 1. Unified API: encrypt → serialize → file → deserialize → decrypt
// ============================================================================

#[test]
fn roundtrip_unified_api_default_config_through_file() {
    let key = [0x42u8; 32];
    let plaintext = b"Practical round-trip test through file system";

    // Step 1: Encrypt with default config
    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    // Step 2: Convert to EncryptedData and serialize to JSON
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

    // Step 3: Write to file
    let file = write_to_tempfile(&json);

    // Step 4: Read from file
    let json_from_file = read_from_tempfile(&file);

    // Step 5: Deserialize
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    // Step 6: Convert to EncryptedOutput and decrypt
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_unified_api_with_use_case_through_file() {
    let key = [0xABu8; 32];
    let plaintext = b"File storage use case round-trip";

    let config =
        CryptoConfig::new().use_case(UseCase::FileStorage).force_scheme(CryptoScheme::Symmetric);
    let encrypted: EncryptedOutput =
        encrypt(plaintext, EncryptKey::Symmetric(&key), config).expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_unified_api_with_security_level_maximum() {
    let key = [0xCDu8; 32];
    let plaintext = b"Maximum security level round-trip";

    let config = CryptoConfig::new()
        .security_level(SecurityLevel::Maximum)
        .force_scheme(CryptoScheme::Symmetric);
    let encrypted: EncryptedOutput =
        encrypt(plaintext, EncryptKey::Symmetric(&key), config).expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_unified_api_empty_plaintext() {
    let key = [0x11u8; 32];
    let plaintext = b"";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_unified_api_large_plaintext() {
    let key = [0x77u8; 32];
    let plaintext = vec![0xFFu8; 128 * 1024]; // 128 KiB

    let encrypted: EncryptedOutput = encrypt(
        &plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn roundtrip_unified_api_binary_data() {
    let key = [0x33u8; 32];
    // All 256 byte values to test binary safety through Base64
    let plaintext: Vec<u8> = (0..=255).collect();

    let encrypted: EncryptedOutput = encrypt(
        &plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// 2. AES-GCM Direct: encrypt_aes_gcm → wrap in EncryptedData → serialize → file → decrypt
// ============================================================================

#[test]
fn roundtrip_aes_gcm_direct_through_file() {
    let key = [0x55u8; 32];
    let plaintext = b"Direct AES-GCM through file persistence";

    // encrypt_aes_gcm returns raw Vec<u8> (nonce || ciphertext || tag)
    let ciphertext =
        encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");

    // Wrap in EncryptedData for serialization (mirrors how unified API stores it)
    let nonce = ciphertext.get(..12).map(<[u8]>::to_vec).unwrap_or_default();
    let tag = ciphertext
        .len()
        .checked_sub(16)
        .and_then(|start| ciphertext.get(start..))
        .map(<[u8]>::to_vec);

    let encrypted_data = EncryptedData {
        data: ciphertext,
        metadata: EncryptedMetadata {
            nonce,
            tag,
            key_id: Some("aes-gcm-direct-key-001".to_string()),
        },
        scheme: "aes-256-gcm".to_string(),
        timestamp: 1700000000,
    };

    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized = deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    // Decrypt using the raw ciphertext from deserialized EncryptedData
    let decrypted = decrypt_aes_gcm(&deserialized.data, &key, SecurityMode::Unverified)
        .expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
    assert_eq!(deserialized.metadata.key_id.as_deref(), Some("aes-gcm-direct-key-001"));
}

// ============================================================================
// 3. Hybrid Encryption: encrypt(Hybrid) → serialize → file → deserialize → decrypt
// ============================================================================

#[test]
fn roundtrip_hybrid_encrypt_through_file() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen failed");
    let plaintext = b"Hybrid ML-KEM-768 + X25519 through file round-trip";

    // Step 1: Encrypt via unified API
    let encrypted = encrypt(plaintext, EncryptKey::Hybrid(&pk), CryptoConfig::new())
        .expect("hybrid encrypt failed");

    // Step 2: Serialize to JSON
    let serializable = SerializableHybridEncrypted::from_encrypted_output(&encrypted);
    let json = serde_json::to_string_pretty(&serializable).expect("serialize failed");

    // Step 3: Write to file
    let file = write_to_tempfile(&json);

    // Step 4: Read from file
    let json_from_file = read_from_tempfile(&file);

    // Step 5: Deserialize
    let deserialized: SerializableHybridEncrypted =
        serde_json::from_str(&json_from_file).expect("deserialize failed");
    let restored = deserialized.to_encrypted_output();

    // Step 6: Verify component sizes survived serialization
    let orig_hybrid = encrypted.hybrid_data.as_ref().unwrap();
    let rest_hybrid = restored.hybrid_data.as_ref().unwrap();
    assert_eq!(rest_hybrid.ml_kem_ciphertext.len(), orig_hybrid.ml_kem_ciphertext.len());
    assert_eq!(rest_hybrid.ecdh_ephemeral_pk.len(), orig_hybrid.ecdh_ephemeral_pk.len());
    assert_eq!(restored.nonce.len(), encrypted.nonce.len());
    assert_eq!(restored.tag.len(), encrypted.tag.len());

    // Step 7: Decrypt
    let decrypted = decrypt(&restored, DecryptKey::Hybrid(&sk), CryptoConfig::new())
        .expect("hybrid decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_hybrid_encrypt_multiple_messages() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen failed");

    let messages: Vec<&[u8]> = vec![
        b"First hybrid message",
        b"Second hybrid message with more data",
        b"Third hybrid message",
    ];

    // Encrypt all, serialize to a JSON array
    let mut serialized_messages = Vec::new();
    for msg in &messages {
        let encrypted = encrypt(msg, EncryptKey::Hybrid(&pk), CryptoConfig::new())
            .expect("hybrid encrypt failed");
        let serializable = SerializableHybridEncrypted::from_encrypted_output(&encrypted);
        serialized_messages.push(serializable);
    }

    let json = serde_json::to_string_pretty(&serialized_messages).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);

    let deserialized: Vec<SerializableHybridEncrypted> =
        serde_json::from_str(&json_from_file).expect("deserialize failed");

    assert_eq!(deserialized.len(), messages.len());

    for (i, ser) in deserialized.iter().enumerate() {
        let restored = ser.to_encrypted_output();
        let decrypted = decrypt(&restored, DecryptKey::Hybrid(&sk), CryptoConfig::new())
            .expect("hybrid decrypt failed");
        assert_eq!(decrypted.as_slice(), messages[i], "message {i} mismatch");
    }
}

// ============================================================================
// 4. Signatures: sign → serialize → file → deserialize → verify
// ============================================================================

#[test]
fn roundtrip_sign_verify_through_file() {
    let message = b"Document that needs persistent signature verification";

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _scheme) = generate_signing_keypair(config).expect("keygen failed");

    // Sign
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

    // Serialize to JSON
    let json = serialize_signed_data(&signed).expect("serialize failed");

    // Write to file
    let file = write_to_tempfile(&json);

    // Read from file
    let json_from_file = read_from_tempfile(&file);

    // Deserialize
    let deserialized = deserialize_signed_data(&json_from_file).expect("deserialize failed");

    // Verify
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&deserialized, config).expect("verify failed");
    assert!(is_valid, "Signature should verify after file round-trip");
}

#[test]
fn roundtrip_sign_verify_maximum_security_through_file() {
    let message = b"Maximum security document signature";

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk, sk, _scheme) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

    let json = serialize_signed_data(&signed).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized = deserialize_signed_data(&json_from_file).expect("deserialize failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let is_valid = verify(&deserialized, config).expect("verify failed");
    assert!(is_valid);
}

// ============================================================================
// 5. Key Persistence: keypair → serialize → file → deserialize → use
// ============================================================================

#[test]
fn roundtrip_keypair_persist_and_use_for_signing() {
    // Generate keypair
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _scheme) = generate_signing_keypair(config).expect("keygen failed");

    // Create a KeyPair for serialization
    let keypair = latticearc::unified_api::types::KeyPair {
        public_key: pk,
        private_key: latticearc::unified_api::types::PrivateKey::new(sk.to_vec()),
    };

    // Serialize keypair to file
    let json = serialize_keypair(&keypair).expect("serialize keypair failed");
    let file = write_to_tempfile(&json);

    // Read keypair from file
    let json_from_file = read_from_tempfile(&file);
    let restored_keypair =
        deserialize_keypair(&json_from_file).expect("deserialize keypair failed");

    // Use restored keypair to sign
    let message = b"Signed with a persisted keypair";
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(
        message,
        restored_keypair.private_key.as_slice(),
        &restored_keypair.public_key,
        config,
    )
    .expect("sign with restored keypair failed");

    // Verify
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed, config).expect("verify failed");
    assert!(is_valid, "Signature with restored keypair should verify");
}

#[test]
fn roundtrip_keypair_persist_and_use_for_encryption() {
    // Use keypair serialization for storing the symmetric key
    let sym_key = [0xEEu8; 32];
    let keypair = latticearc::unified_api::types::KeyPair {
        public_key: sym_key.to_vec(),
        private_key: latticearc::unified_api::types::PrivateKey::new(sym_key.to_vec()),
    };

    let json = serialize_keypair(&keypair).expect("serialize keypair failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let restored = deserialize_keypair(&json_from_file).expect("deserialize keypair failed");

    // Use restored key for encryption
    let plaintext = b"Encrypted with persisted key";
    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&restored.public_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let decrypted = decrypt(
        &encrypted,
        DecryptKey::Symmetric(restored.private_key.as_slice()),
        CryptoConfig::new(),
    )
    .expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// 6. Multi-Message Store: multiple encrypted messages in one file
// ============================================================================

#[test]
fn roundtrip_multi_message_store_selective_decrypt() {
    let key = [0x99u8; 32];

    let messages = vec![
        ("invoice-001", "Invoice: $1,234.56 for services rendered"),
        ("medical-record-042", "Patient: John Doe, Blood Type: O+"),
        ("legal-brief-007", "Confidential legal brief for case #12345"),
        ("personal-note", "Remember to buy groceries"),
    ];

    // Encrypt and store all messages
    let mut store = EncryptedMessageStore { version: "1.0".to_string(), messages: Vec::new() };

    for (label, msg) in &messages {
        let encrypted: EncryptedOutput = encrypt(
            msg.as_bytes(),
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt failed");
        let encrypted_data: EncryptedData = encrypted.into();
        let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
        store.messages.push(StoredMessage { label: label.to_string(), encrypted_json: json });
    }

    // Write entire store to file
    let store_json = serde_json::to_string_pretty(&store).expect("serialize store failed");
    let file = write_to_tempfile(&store_json);

    // Read store from file
    let json_from_file = read_from_tempfile(&file);
    let restored_store: EncryptedMessageStore =
        serde_json::from_str(&json_from_file).expect("deserialize store failed");

    assert_eq!(restored_store.version, "1.0");
    assert_eq!(restored_store.messages.len(), 4);

    // Selectively decrypt just the medical record (by label lookup)
    let medical = restored_store
        .messages
        .iter()
        .find(|m| m.label == "medical-record-042")
        .expect("medical record not found");

    let deserialized: EncryptedData =
        deserialize_encrypted_data(&medical.encrypted_json).expect("deserialize failed");
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");

    assert_eq!(String::from_utf8(decrypted).unwrap(), "Patient: John Doe, Blood Type: O+");

    // Decrypt all and verify
    for (i, stored) in restored_store.messages.iter().enumerate() {
        let deserialized: EncryptedData =
            deserialize_encrypted_data(&stored.encrypted_json).expect("deserialize failed");
        let deserialized_output: EncryptedOutput =
            deserialized.try_into().expect("scheme should be valid");
        let decrypted =
            decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
                .expect("decrypt failed");
        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            messages[i].1,
            "message '{}' mismatch",
            messages[i].0
        );
    }
}

#[test]
fn roundtrip_multi_message_different_keys() {
    let keys: Vec<[u8; 32]> = vec![[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
    let messages = [
        "Message encrypted with key A",
        "Message encrypted with key B",
        "Message encrypted with key C",
    ];

    // Encrypt each message with a different key, using key_id to track which key
    let mut stored_messages = Vec::new();
    for (i, (msg, key)) in messages.iter().zip(keys.iter()).enumerate() {
        let mut encrypted: EncryptedOutput = encrypt(
            msg.as_bytes(),
            EncryptKey::Symmetric(key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt failed");
        // Set key_id to identify which key was used
        encrypted.key_id = Some(format!("key-{}", (b'A' + u8::try_from(i).unwrap()) as char));

        let encrypted_data: EncryptedData = encrypted.into();
        let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
        stored_messages.push(json);
    }

    let all_json = serde_json::to_string_pretty(&stored_messages).expect("serialize all failed");
    let file = write_to_tempfile(&all_json);
    let json_from_file = read_from_tempfile(&file);
    let restored: Vec<String> = serde_json::from_str(&json_from_file).expect("deserialize failed");

    // Build a key lookup table
    let key_map: HashMap<String, [u8; 32]> = [
        ("key-A".to_string(), keys[0]),
        ("key-B".to_string(), keys[1]),
        ("key-C".to_string(), keys[2]),
    ]
    .into_iter()
    .collect();

    // Decrypt each message by looking up the correct key from key_id
    for (i, json) in restored.iter().enumerate() {
        let deserialized: EncryptedData =
            deserialize_encrypted_data(json).expect("deserialize failed");
        let key_id = deserialized.metadata.key_id.as_ref().expect("key_id missing");
        let key = key_map.get(key_id).expect("key not found");

        let deserialized_output: EncryptedOutput =
            deserialized.try_into().expect("scheme should be valid");
        let decrypted =
            decrypt(&deserialized_output, DecryptKey::Symmetric(key), CryptoConfig::new())
                .expect("decrypt failed");
        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            messages[i],
            "message {i} mismatch after key_id lookup"
        );
    }
}

// ============================================================================
// 7. Metadata Inspection: verify metadata readable without key
// ============================================================================

#[test]
fn metadata_readable_without_decryption_key() {
    let key = [0xDDu8; 32];
    let plaintext = b"Secret data that should not be readable from metadata";

    let mut encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    encrypted.key_id = Some("production-key-2026".to_string());

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);

    // Parse JSON without decrypting — an adversary or key-management system
    // can read the metadata fields
    let raw: serde_json::Value = serde_json::from_str(&json_from_file).expect("JSON parse failed");

    // Verify metadata fields are accessible
    assert_eq!(raw["scheme"].as_str().unwrap(), "aes-256-gcm");
    assert!(raw["timestamp"].as_u64().unwrap() > 0);
    assert_eq!(raw["metadata"]["key_id"].as_str().unwrap(), "production-key-2026");
    assert!(raw["metadata"]["nonce"].as_str().is_some());
    assert!(raw["metadata"]["tag"].as_str().is_some());

    // The encrypted data field exists but is just base64 — not plaintext
    let data_b64 = raw["data"].as_str().unwrap();
    assert!(!data_b64.is_empty());
    // Plaintext should NOT appear anywhere in the JSON
    assert!(
        !json_from_file.contains("Secret data"),
        "Plaintext should not be visible in serialized output"
    );
}

#[test]
fn metadata_scheme_correctly_identifies_algorithm() {
    let key = [0x44u8; 32];

    // Test with different use cases — all should produce aes-256-gcm
    // (unified API falls back to AES-GCM for symmetric keys)
    let use_cases = vec![UseCase::FileStorage, UseCase::SecureMessaging, UseCase::IoTDevice];

    for use_case in use_cases {
        let config =
            CryptoConfig::new().use_case(use_case.clone()).force_scheme(CryptoScheme::Symmetric);
        let encrypted: EncryptedOutput =
            encrypt(b"test", EncryptKey::Symmetric(&key), config).expect("encrypt failed");
        let encrypted_data: EncryptedData = encrypted.into();
        let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

        let raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
        let scheme = raw["scheme"].as_str().unwrap();

        // Unified API with symmetric key always produces AES-256-GCM
        assert_eq!(
            scheme, "aes-256-gcm",
            "Use case {:?} should produce aes-256-gcm scheme in metadata",
            use_case
        );
    }
}

// ============================================================================
// 8. Cross-Config: encrypt with one config, decrypt ignores config
// ============================================================================

#[test]
fn roundtrip_encrypt_with_usecase_decrypt_with_default() {
    let key = [0x88u8; 32];
    let plaintext = b"Encrypt with specific config, decrypt with default";

    // Encrypt with use case config
    let config = CryptoConfig::new()
        .use_case(UseCase::SecureMessaging)
        .force_scheme(CryptoScheme::Symmetric);
    let encrypted: EncryptedOutput =
        encrypt(plaintext, EncryptKey::Symmetric(&key), config).expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    // Decrypt with completely different config — should work because
    // algorithm comes from EncryptedData.scheme, not CryptoConfig
    let different_config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), different_config)
        .expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_encrypt_with_maximum_decrypt_with_standard() {
    let key = [0x66u8; 32];
    let plaintext = b"Security level in config doesn't affect decrypt";

    let config = CryptoConfig::new()
        .security_level(SecurityLevel::Maximum)
        .force_scheme(CryptoScheme::Symmetric);
    let encrypted: EncryptedOutput =
        encrypt(plaintext, EncryptKey::Symmetric(&key), config).expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    // Different security level for decrypt — still works
    let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted =
        decrypt(&deserialized_output, DecryptKey::Symmetric(&key), config).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// 9. AAD Context Binding: encrypt with AAD → file → decrypt with same AAD
// ============================================================================

#[test]
fn roundtrip_aes_gcm_with_aad_through_file() {
    let key = [0xBBu8; 32];
    let plaintext = b"Context-bound encrypted data";
    let aad = b"version:1;sender:alice;receiver:bob";

    // Encrypt with AAD
    let ciphertext = encrypt_aes_gcm_with_aad(plaintext, &key, aad, SecurityMode::Unverified)
        .expect("encrypt with aad failed");

    // Wrap in EncryptedData with AAD stored in key_id (as an example of
    // how a user might persist the AAD context)
    let nonce = ciphertext.get(..12).map(<[u8]>::to_vec).unwrap_or_default();

    #[derive(Serialize, Deserialize)]
    struct AadEncryptedFile {
        encrypted_data: String, // base64 of raw ciphertext
        aad: String,            // hex of AAD
        scheme: String,
        nonce: String, // base64
    }

    let file_data = AadEncryptedFile {
        encrypted_data: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        aad: hex::encode(aad),
        scheme: "aes-256-gcm-with-aad".to_string(),
        nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
    };

    let json = serde_json::to_string_pretty(&file_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let restored: AadEncryptedFile =
        serde_json::from_str(&json_from_file).expect("deserialize failed");

    // Recover ciphertext and AAD from file
    let restored_ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&restored.encrypted_data)
        .expect("base64 decode failed");
    let restored_aad = hex::decode(&restored.aad).expect("hex decode failed");

    // Decrypt with correct AAD
    let decrypted = decrypt_aes_gcm_with_aad(
        &restored_ciphertext,
        &key,
        &restored_aad,
        SecurityMode::Unverified,
    )
    .expect("decrypt with aad failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_aes_gcm_with_aad_wrong_aad_fails() {
    let key = [0xCCu8; 32];
    let plaintext = b"AAD tamper detection test";
    let aad = b"correct-context";

    let ciphertext = encrypt_aes_gcm_with_aad(plaintext, &key, aad, SecurityMode::Unverified)
        .expect("encrypt failed");

    // Try to decrypt with wrong AAD — should fail
    let wrong_aad = b"tampered-context";
    let result = decrypt_aes_gcm_with_aad(&ciphertext, &key, wrong_aad, SecurityMode::Unverified);
    assert!(result.is_err(), "Decryption with wrong AAD should fail");
}

// ============================================================================
// 10. Tamper Detection: modify serialized data, verify decrypt fails
// ============================================================================

#[test]
fn tamper_detection_modified_ciphertext_in_file() {
    let key = [0xAAu8; 32];
    let plaintext = b"Tamper-evident encrypted data";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

    // Parse JSON and modify the encrypted data
    let mut raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
    let data_b64 = raw["data"].as_str().unwrap().to_string();

    // Tamper: flip a character in the base64 data
    let mut tampered = data_b64.into_bytes();
    if let Some(byte) = tampered.get_mut(10) {
        *byte = if *byte == b'A' { b'B' } else { b'A' };
    }
    raw["data"] = serde_json::Value::String(String::from_utf8(tampered).unwrap());

    let tampered_json = serde_json::to_string(&raw).expect("re-serialize failed");
    let file = write_to_tempfile(&tampered_json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    // Decrypt should fail due to authentication tag mismatch
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let result = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new());
    assert!(result.is_err(), "Decryption of tampered ciphertext should fail");
}

#[test]
fn tamper_detection_modified_nonce_in_file() {
    let key = [0xBBu8; 32];
    let plaintext = b"Nonce tamper detection";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

    // Parse and modify the nonce
    let mut raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
    raw["metadata"]["nonce"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode([0xFFu8; 12]));

    let tampered_json = serde_json::to_string(&raw).expect("re-serialize failed");

    // The EncryptedData.data field contains the real nonce in the first 12 bytes,
    // so changing metadata.nonce doesn't affect decrypt (it uses data directly).
    // This test documents the current behavior.
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&tampered_json).expect("deserialize failed");

    // Decrypt uses encrypted.data directly (which has nonce embedded), so
    // modifying metadata.nonce alone may not cause failure. This is expected
    // because the nonce in metadata is informational — the authoritative nonce
    // is inside the data blob.
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let result = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new());
    // Document the actual behavior: decrypt uses data blob, not metadata.nonce
    assert!(
        result.is_ok(),
        "Modifying metadata.nonce alone doesn't break decrypt (nonce is in data blob)"
    );
}

#[test]
fn tamper_detection_wrong_key_fails() {
    let key = [0x11u8; 32];
    let wrong_key = [0x22u8; 32];
    let plaintext = b"Wrong key should fail authentication";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let result =
        decrypt(&deserialized_output, DecryptKey::Symmetric(&wrong_key), CryptoConfig::new());
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn tamper_detection_truncated_ciphertext() {
    let key = [0x33u8; 32];
    let plaintext = b"Truncation detection test";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

    // Parse and truncate the data
    let mut raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
    let data_b64 = raw["data"].as_str().unwrap();
    let truncated = &data_b64[..data_b64.len() / 2];
    raw["data"] = serde_json::Value::String(truncated.to_string());

    let tampered_json = serde_json::to_string(&raw).expect("re-serialize failed");

    // Deserialization may succeed (it's valid base64/JSON)
    // but decryption should fail
    if let Ok(deserialized) = deserialize_encrypted_data(&tampered_json) {
        let deserialized_output: EncryptedOutput =
            deserialized.try_into().expect("scheme should be valid");
        let result =
            decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err(), "Decryption of truncated data should fail");
    }
    // If deserialization itself fails, that's also acceptable
}

#[test]
fn tamper_detection_modified_scheme_field() {
    let key = [0x44u8; 32];
    let plaintext = b"Scheme field tamper test";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

    // Change scheme to a valid but wrong scheme (AES-GCM data with ChaCha20 scheme)
    // With EncryptionScheme enum, unknown strings default to AES-256-GCM on parse,
    // so we use a valid alternative scheme to test mismatch detection.
    let mut raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
    raw["scheme"] = serde_json::Value::String("chacha20-poly1305".to_string());

    let tampered_json = serde_json::to_string(&raw).expect("re-serialize failed");
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&tampered_json).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let result = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new());
    assert!(result.is_err(), "Decryption with wrong scheme should fail");
}

// ============================================================================
// 11. Signed Data Tamper Detection
// ============================================================================

#[test]
fn tamper_detection_modified_signed_data() {
    let message = b"Tamper-evident signed document";

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

    let json = serialize_signed_data(&signed).expect("serialize failed");

    // Parse and modify the signed data
    let mut raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
    let data_b64 = raw["data"].as_str().unwrap().to_string();
    let mut tampered = data_b64.into_bytes();
    if let Some(byte) = tampered.get_mut(5) {
        *byte = if *byte == b'A' { b'B' } else { b'A' };
    }
    raw["data"] = serde_json::Value::String(String::from_utf8(tampered).unwrap());

    let tampered_json = serde_json::to_string(&raw).expect("re-serialize failed");
    let deserialized = deserialize_signed_data(&tampered_json).expect("deserialize failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = verify(&deserialized, config);

    // Either returns false (invalid signature) or returns an error
    if let Ok(is_valid) = result {
        assert!(!is_valid, "Tampered signed data should not verify");
    }
    // Err is also acceptable for tampered data
}

// ============================================================================
// 12. Interop Simulation: encrypt on "sender" → file transfer → decrypt on "receiver"
// ============================================================================

#[test]
fn interop_simulation_sender_receiver_symmetric() {
    // Simulate: sender encrypts, writes to file, file is transferred,
    // receiver reads from file and decrypts with pre-shared key

    let shared_key = [0x56u8; 32];

    // === SENDER SIDE ===
    let sender_plaintext = b"Confidential report Q4 2026";
    let sender_encrypted: EncryptedOutput = encrypt(
        sender_plaintext,
        EncryptKey::Symmetric(&shared_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("sender encrypt failed");
    let sender_encrypted_data: EncryptedData = sender_encrypted.into();
    let sender_json =
        serialize_encrypted_data(&sender_encrypted_data).expect("sender serialize failed");
    let transfer_file = write_to_tempfile(&sender_json);

    // === FILE TRANSFER (simulated by reading the same file) ===

    // === RECEIVER SIDE ===
    let receiver_json = read_from_tempfile(&transfer_file);
    let receiver_deserialized: EncryptedData =
        deserialize_encrypted_data(&receiver_json).expect("receiver deserialize failed");
    let receiver_output: EncryptedOutput =
        receiver_deserialized.try_into().expect("scheme should be valid");
    let receiver_plaintext =
        decrypt(&receiver_output, DecryptKey::Symmetric(&shared_key), CryptoConfig::new())
            .expect("receiver decrypt failed");

    assert_eq!(receiver_plaintext.as_slice(), sender_plaintext);
}

#[test]
fn interop_simulation_sender_receiver_hybrid() {
    // Simulate: receiver generates keypair, shares public key,
    // sender encrypts with public key, receiver decrypts with secret key

    // === RECEIVER generates keypair ===
    let (receiver_pk, receiver_sk) = generate_hybrid_keypair().expect("keygen failed");

    // === SENDER encrypts with receiver's public key ===
    let sender_plaintext = b"Hybrid encrypted message for receiver";
    let sender_encrypted =
        encrypt(sender_plaintext, EncryptKey::Hybrid(&receiver_pk), CryptoConfig::new())
            .expect("sender hybrid encrypt failed");

    let serializable = SerializableHybridEncrypted::from_encrypted_output(&sender_encrypted);
    let sender_json = serde_json::to_string_pretty(&serializable).expect("serialize failed");
    let transfer_file = write_to_tempfile(&sender_json);

    // === RECEIVER decrypts ===
    let receiver_json = read_from_tempfile(&transfer_file);
    let deserialized: SerializableHybridEncrypted =
        serde_json::from_str(&receiver_json).expect("deserialize failed");
    let restored = deserialized.to_encrypted_output();

    let receiver_plaintext =
        decrypt(&restored, DecryptKey::Hybrid(&receiver_sk), CryptoConfig::new())
            .expect("receiver hybrid decrypt failed");

    assert_eq!(receiver_plaintext.as_slice(), sender_plaintext);
}

#[test]
fn interop_simulation_sign_and_encrypt_bundle() {
    // Simulate: sender signs a document, then encrypts the signature bundle,
    // receiver decrypts, then verifies the signature

    let shared_key = [0x78u8; 32];
    let document = b"Contract: I agree to pay $10,000";

    // === SENDER: sign then encrypt ===
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(document, &sk, &pk, config).expect("sign failed");

    // Serialize the signed data, then encrypt the serialized form
    let signed_json = serialize_signed_data(&signed).expect("serialize signed failed");
    let encrypted: EncryptedOutput = encrypt(
        signed_json.as_bytes(),
        EncryptKey::Symmetric(&shared_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt signed bundle failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let encrypted_json =
        serialize_encrypted_data(&encrypted_data).expect("serialize encrypted failed");

    let transfer_file = write_to_tempfile(&encrypted_json);

    // === RECEIVER: decrypt then verify ===
    let receiver_json = read_from_tempfile(&transfer_file);
    let receiver_deserialized: EncryptedData =
        deserialize_encrypted_data(&receiver_json).expect("deserialize encrypted failed");
    let receiver_output: EncryptedOutput =
        receiver_deserialized.try_into().expect("scheme should be valid");
    let decrypted_bundle =
        decrypt(&receiver_output, DecryptKey::Symmetric(&shared_key), CryptoConfig::new())
            .expect("decrypt bundle failed");

    let signed_json_str = String::from_utf8(decrypted_bundle).expect("UTF-8 failed");
    let restored_signed =
        deserialize_signed_data(&signed_json_str).expect("deserialize signed failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&restored_signed, config).expect("verify failed");
    assert!(is_valid, "Signature should verify after encrypt→file→decrypt round-trip");
}

// ============================================================================
// 13. Double Serialization Stability
// ============================================================================

#[test]
fn double_serialization_idempotent() {
    let key = [0x55u8; 32];
    let plaintext = b"Double serialization stability test";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    // Serialize → deserialize → serialize again (all using EncryptedData)
    let encrypted_data: EncryptedData = encrypted.into();
    let json1 = serialize_encrypted_data(&encrypted_data).expect("serialize 1 failed");
    let round1 = deserialize_encrypted_data(&json1).expect("deserialize 1 failed");
    let json2 = serialize_encrypted_data(&round1).expect("serialize 2 failed");
    let round2 = deserialize_encrypted_data(&json2).expect("deserialize 2 failed");
    let json3 = serialize_encrypted_data(&round2).expect("serialize 3 failed");

    // JSON should be identical after the first round-trip
    assert_eq!(json1, json2, "First and second serialization should be identical");
    assert_eq!(json2, json3, "Second and third serialization should be identical");

    // And the data should still decrypt
    let round2_output: EncryptedOutput = round2.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&round2_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// 14. Concurrent File Access Pattern
// ============================================================================

#[test]
fn roundtrip_concurrent_encrypt_serialize_pattern() {
    // Simulates a pattern where multiple threads encrypt different data
    // with the same key, then all results are collected and written

    let key = [0x77u8; 32];
    let messages: Vec<String> = (0..10).map(|i| format!("Concurrent message number {i}")).collect();

    let encrypted_jsons: Vec<String> = messages
        .iter()
        .map(|msg| {
            let encrypted: EncryptedOutput = encrypt(
                msg.as_bytes(),
                EncryptKey::Symmetric(&key),
                CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
            )
            .expect("encrypt failed");
            let encrypted_data: EncryptedData = encrypted.into();
            serialize_encrypted_data(&encrypted_data).expect("serialize failed")
        })
        .collect();

    // Write all to a single file as JSON array
    let all_json = serde_json::to_string_pretty(&encrypted_jsons).expect("array serialize failed");
    let file = write_to_tempfile(&all_json);

    // Read back and decrypt all
    let json_from_file = read_from_tempfile(&file);
    let restored: Vec<String> = serde_json::from_str(&json_from_file).expect("deserialize failed");

    assert_eq!(restored.len(), 10);

    for (i, json) in restored.iter().enumerate() {
        let deserialized: EncryptedData =
            deserialize_encrypted_data(json).expect("deserialize failed");
        let deserialized_output: EncryptedOutput =
            deserialized.try_into().expect("scheme should be valid");
        let decrypted =
            decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
                .expect("decrypt failed");
        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            messages[i],
            "concurrent message {i} mismatch"
        );
    }
}

// ============================================================================
// 15. Version/Format Forward Compatibility
// ============================================================================

#[test]
fn forward_compat_extra_json_fields_ignored() {
    let key = [0x99u8; 32];
    let plaintext = b"Forward compatibility test";

    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");
    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");

    // Simulate a future version adding extra fields
    let mut raw: serde_json::Value = serde_json::from_str(&json).expect("parse failed");
    raw["format_version"] = serde_json::Value::String("2.0".to_string());
    raw["compression"] = serde_json::Value::String("none".to_string());
    raw["metadata"]["encryption_context"] = serde_json::Value::String("test".to_string());

    let future_json = serde_json::to_string(&raw).expect("re-serialize failed");
    let file = write_to_tempfile(&future_json);
    let json_from_file = read_from_tempfile(&file);

    // Current version should ignore extra fields and still decrypt
    let deserialized: EncryptedData = deserialize_encrypted_data(&json_from_file)
        .expect("deserialize with extra fields should succeed");
    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt should succeed despite extra fields");

    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// 16. Unicode and Special Content
// ============================================================================

#[test]
fn roundtrip_unicode_plaintext_through_file() {
    let key = [0x22u8; 32];
    let plaintext = "日本語テスト 🔐 Ñoño résumé Ελληνικά العربية";

    let encrypted: EncryptedOutput = encrypt(
        plaintext.as_bytes(),
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    let decrypted_str = String::from_utf8(decrypted).expect("UTF-8 failed");

    assert_eq!(decrypted_str, plaintext);
}

#[test]
fn roundtrip_json_plaintext_through_file() {
    let key = [0x33u8; 32];
    let plaintext = r#"{"user": "alice", "secret": "p@$$w0rd!", "data": [1, 2, 3]}"#;

    let encrypted: EncryptedOutput = encrypt(
        plaintext.as_bytes(),
        EncryptKey::Symmetric(&key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let encrypted_data: EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let deserialized: EncryptedData =
        deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    let deserialized_output: EncryptedOutput =
        deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&deserialized_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt failed");
    let decrypted_str = String::from_utf8(decrypted).expect("UTF-8 failed");

    assert_eq!(decrypted_str, plaintext);

    // Verify the decrypted JSON is valid
    let parsed: serde_json::Value =
        serde_json::from_str(&decrypted_str).expect("JSON parse failed");
    assert_eq!(parsed["user"], "alice");
}
