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
//! - **Hybrid Encryption**: encrypt(Hybrid) → serialize components → file → decrypt
//! - **Signatures**: sign_with_key() → serialize → file → deserialize → verify()
//! - **Key Persistence**: keypair → serialize → file → deserialize → use (incl. portable
//!   key format)
//! - **AAD Context Binding**: encrypt_aes_gcm_with_aad round-trip through files
//!
//! Run with:
//! ```bash
//! cargo test --package latticearc-tests --test practical_roundtrip --all-features --release
//! ```

#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::print_stdout)]
#![allow(missing_docs)]
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
    EncryptedOutput,
    EncryptionScheme,
    HybridComponents,
    SecurityLevel,
    SecurityMode,
    UseCase,
    // Unified API
    decrypt,
    // AES-GCM direct
    decrypt_aes_gcm_with_aad,
    // Serialization
    deserialize_keypair,
    deserialize_signed_data,
    encrypt,
    // AES-GCM with AAD
    encrypt_aes_gcm_with_aad,
    generate_hybrid_keypair,
    // Signing
    generate_signing_keypair,
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
        let hybrid = output.hybrid_data().expect("hybrid_data must be present");
        Self {
            kem_ciphertext: STANDARD.encode(hybrid.ml_kem_ciphertext()),
            ecdh_ephemeral_pk: STANDARD.encode(hybrid.ecdh_ephemeral_pk()),
            symmetric_ciphertext: STANDARD.encode(output.ciphertext()),
            nonce: STANDARD.encode(output.nonce()),
            tag: STANDARD.encode(output.tag()),
        }
    }

    fn to_encrypted_output(&self) -> EncryptedOutput {
        use base64::{Engine, engine::general_purpose::STANDARD};
        EncryptedOutput::new(
            EncryptionScheme::HybridMlKem768Aes256Gcm,
            STANDARD.decode(&self.symmetric_ciphertext).unwrap(),
            STANDARD.decode(&self.nonce).unwrap(),
            STANDARD.decode(&self.tag).unwrap(),
            Some(HybridComponents::new(
                STANDARD.decode(&self.kem_ciphertext).unwrap(),
                STANDARD.decode(&self.ecdh_ephemeral_pk).unwrap(),
            )),
            chrono::Utc::now().timestamp().unsigned_abs(),
            None,
        )
    }
}

// ============================================================================
// Hybrid Encryption: encrypt(Hybrid) → serialize → file → deserialize → decrypt
// ============================================================================

#[test]
fn roundtrip_hybrid_encrypt_through_file_succeeds() {
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
    let orig_hybrid = encrypted.hybrid_data().unwrap();
    let rest_hybrid = restored.hybrid_data().unwrap();
    assert_eq!(rest_hybrid.ml_kem_ciphertext().len(), orig_hybrid.ml_kem_ciphertext().len());
    assert_eq!(rest_hybrid.ecdh_ephemeral_pk().len(), orig_hybrid.ecdh_ephemeral_pk().len());
    assert_eq!(restored.nonce().len(), encrypted.nonce().len());
    assert_eq!(restored.tag().len(), encrypted.tag().len());

    // Step 7: Decrypt
    let decrypted = decrypt(&restored, DecryptKey::Hybrid(&sk), CryptoConfig::new())
        .expect("hybrid decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn roundtrip_hybrid_encrypt_multiple_messages_succeeds() {
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
fn roundtrip_sign_verify_through_file_succeeds() {
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
fn roundtrip_sign_verify_maximum_security_through_file_succeeds() {
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
fn roundtrip_keypair_persist_and_use_for_signing_succeeds() {
    // Generate keypair
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _scheme) = generate_signing_keypair(config).expect("keygen failed");

    // Create a KeyPair for serialization
    let keypair = latticearc::unified_api::types::KeyPair::new(
        latticearc::PublicKey::new(pk),
        latticearc::unified_api::types::PrivateKey::new(sk.to_vec()),
    );

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
        restored_keypair.private_key().expose_secret(),
        restored_keypair.public_key().as_slice(),
        config,
    )
    .expect("sign with restored keypair failed");

    // Verify
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed, config).expect("verify failed");
    assert!(is_valid, "Signature with restored keypair should verify");
}

#[test]
fn roundtrip_keypair_persist_and_use_for_encryption_succeeds() {
    // Use keypair serialization for storing the symmetric key
    let sym_key = [0xEEu8; 32];
    let keypair = latticearc::unified_api::types::KeyPair::new(
        latticearc::PublicKey::new(sym_key.to_vec()),
        latticearc::unified_api::types::PrivateKey::new(sym_key.to_vec()),
    );

    let json = serialize_keypair(&keypair).expect("serialize keypair failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_tempfile(&file);
    let restored = deserialize_keypair(&json_from_file).expect("deserialize keypair failed");

    // Use restored key for encryption
    let plaintext = b"Encrypted with persisted key";
    let encrypted: EncryptedOutput = encrypt(
        plaintext,
        EncryptKey::Symmetric(restored.public_key().as_slice()),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt failed");

    let decrypted = decrypt(
        &encrypted,
        DecryptKey::Symmetric(restored.private_key().expose_secret()),
        CryptoConfig::new(),
    )
    .expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// Key Persistence via PortableKey — the standard key format
// ============================================================================

/// E2E: Generate signing keypair → persist as PortableKey JSON → load from
/// file → sign → verify. Two-process simulation: original keys are dropped
/// before the signing/verifying process loads from the file.
#[test]
fn roundtrip_portable_key_persist_and_sign_succeeds() {
    use latticearc::hybrid::sig_hybrid;
    use latticearc::{KeyAlgorithm, PortableKey};

    // === Process A: Generate keypair, export to files ===
    let (pk, sk) = sig_hybrid::generate_keypair().expect("sig keygen");
    let (portable_pk, portable_sk) =
        PortableKey::from_hybrid_sig_keypair(UseCase::LegalDocuments, &pk, &sk)
            .expect("from_hybrid_sig_keypair");

    let pk_file = write_to_tempfile(&portable_pk.to_json().unwrap());
    let sk_file = write_to_tempfile(&portable_sk.to_json().unwrap());
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // === Process B: Load SK from file, sign ===
    let sk_json = read_from_tempfile(&sk_file);
    let sk_portable = PortableKey::from_json(&sk_json).expect("deserialize SK");
    assert_eq!(sk_portable.algorithm(), KeyAlgorithm::HybridMlDsa65Ed25519);
    assert_eq!(sk_portable.use_case(), Some(UseCase::LegalDocuments));

    let restored_sk = sk_portable.to_hybrid_sig_secret_key().expect("extract SK");

    let message = b"Contract signed via PortableKey format";
    let signature = sig_hybrid::sign(&restored_sk, message).expect("sign");

    // === Process C: Load PK from file, verify ===
    let pk_json = read_from_tempfile(&pk_file);
    let pk_portable = PortableKey::from_json(&pk_json).expect("deserialize PK");
    let hybrid_pk = pk_portable.to_hybrid_sig_public_key().expect("extract PK");
    let valid = sig_hybrid::verify(&hybrid_pk, message, &signature).expect("verify");

    assert!(valid, "Signature must verify with PortableKey-restored keys");

    println!(
        "[PROOF] {{\"test\":\"roundtrip_portable_key_persist_and_sign\",\
         \"category\":\"practical-roundtrip\",\
         \"use_case\":\"legal-documents\",\
         \"algorithm\":\"hybrid-ml-dsa-65-ed25519\",\
         \"cross_process_verify\":{valid},\
         \"status\":\"PASS\"}}"
    );
}

/// E2E: Generate hybrid KEM keypair → persist as PortableKey JSON → load
/// from file → encapsulate → decapsulate. Two-process simulation.
#[test]
fn roundtrip_portable_key_persist_and_encrypt_succeeds() {
    use latticearc::hybrid::kem_hybrid;
    use latticearc::{KeyAlgorithm, PortableKey};

    // === Process A: Generate keypair, export to files ===
    let (pk, sk) = kem_hybrid::generate_keypair().expect("kem keygen");
    let (portable_pk, portable_sk) =
        PortableKey::from_hybrid_kem_keypair(UseCase::FileStorage, &pk, &sk).unwrap();

    let pk_file = write_to_tempfile(&portable_pk.to_json().unwrap());
    let sk_file = write_to_tempfile(&portable_sk.to_json().unwrap());
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // === Process B: Load PK from file, encapsulate ===
    let pk_json = read_from_tempfile(&pk_file);
    let pk_portable = PortableKey::from_json(&pk_json).expect("deserialize PK");
    assert_eq!(pk_portable.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
    assert_eq!(pk_portable.use_case(), Some(UseCase::FileStorage));

    let hybrid_pk = pk_portable.to_hybrid_public_key().expect("extract PK");
    let encapsulated = kem_hybrid::encapsulate(&hybrid_pk).expect("encapsulate");
    let sender_ss = encapsulated.expose_secret().to_vec();

    // === Process A: Load SK + PK from files, decapsulate ===
    let sk_json = read_from_tempfile(&sk_file);
    let sk_portable = PortableKey::from_json(&sk_json).expect("deserialize SK");
    // Public key stored in SK metadata at keygen time (PKCS#12 pattern) — no separate PK file needed
    let hybrid_sk = sk_portable.to_hybrid_secret_key().expect("reconstruct SK");
    let receiver_ss = kem_hybrid::decapsulate(&hybrid_sk, &encapsulated).expect("decapsulate");

    let match_ok = receiver_ss.expose_secret() == sender_ss.as_slice();
    assert!(match_ok, "Shared secrets must match via PortableKey persistence");

    println!(
        "[PROOF] {{\"test\":\"roundtrip_portable_key_persist_and_encrypt\",\
         \"category\":\"practical-roundtrip\",\
         \"use_case\":\"file-storage\",\
         \"algorithm\":\"hybrid-ml-kem-768-x25519\",\
         \"shared_secret_bytes\":{},\
         \"cross_process_kem_match\":{match_ok},\
         \"status\":\"PASS\"}}",
        receiver_ss.len(),
    );
}

/// E2E: PortableKey symmetric key persistence — store AES-256 key,
/// load from file, encrypt, decrypt.
#[test]
fn roundtrip_portable_key_symmetric_encrypt_succeeds() {
    use latticearc::{KeyAlgorithm, KeyData, KeyType, PortableKey};

    // === Process A: Create symmetric key, save to file ===
    // Symmetric keys use explicit algorithm (not UseCase resolution,
    // which resolves to KEM/signature algorithms)
    let sym_key = [0xEEu8; 32];
    let portable =
        PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&sym_key));
    let key_file = write_to_tempfile(&portable.to_json().unwrap());
    drop(portable);

    // === Process B: Load key from file, encrypt ===
    let key_json = read_from_tempfile(&key_file);
    let loaded = PortableKey::from_json(&key_json).expect("deserialize");
    // UseCase::DatabaseEncryption resolves to HybridMlKem768X25519 for KEM,
    // but for symmetric keys we use the raw algorithm
    assert_eq!(loaded.key_type(), KeyType::Symmetric);

    let restored_key = loaded.key_data().decode_raw().unwrap();
    assert_eq!(restored_key.len(), 32);

    let plaintext = b"Database row encrypted with PortableKey";
    let encrypted = encrypt(
        plaintext,
        EncryptKey::Symmetric(&restored_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt");

    let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&restored_key), CryptoConfig::new())
        .expect("decrypt");

    let match_ok = decrypted.as_slice() == plaintext;
    assert!(match_ok);

    println!(
        "[PROOF] {{\"test\":\"roundtrip_portable_key_symmetric_encrypt\",\
         \"category\":\"practical-roundtrip\",\
         \"use_case\":\"database-encryption\",\
         \"key_type\":\"symmetric\",\
         \"plaintext_len\":{},\
         \"roundtrip_match\":{match_ok},\
         \"status\":\"PASS\"}}",
        plaintext.len(),
    );
}

// ============================================================================
// Hybrid full encrypt → serialize → deserialize → decrypt (real-world mirror)
// ============================================================================

/// E2E: Hybrid encrypt with public key → serialize encrypted output + secret key
/// to JSON → drop everything → deserialize both from JSON → decrypt with secret
/// key only (no public key file). This mirrors the real-world usage pattern where
/// a CLI or service stores keys on disk and decrypts in a separate process.
#[test]
fn roundtrip_hybrid_encrypt_serialize_decrypt_from_sk_only_succeeds() {
    use latticearc::PortableKey;
    use latticearc::hybrid::kem_hybrid;
    use latticearc::unified_api::serialization::{
        deserialize_encrypted_output, serialize_encrypted_output,
    };

    let plaintext = b"Cross-process hybrid encrypt/decrypt roundtrip test";

    // === Process A: Generate keypair, export to JSON ===
    let (pk, sk) = kem_hybrid::generate_keypair().expect("keygen");
    let (pk_portable, sk_portable) =
        PortableKey::from_hybrid_kem_keypair(UseCase::CloudStorage, &pk, &sk).expect("export");

    let pk_json: String = pk_portable.to_json().expect("pk json");
    let sk_json: String = sk_portable.to_json().expect("sk json");

    // Drop the in-memory keys — simulate separate processes
    drop(pk);
    drop(sk);
    drop(pk_portable);
    drop(sk_portable);

    // === Process B: Load public key from JSON, encrypt via unified API ===
    let pk_loaded = PortableKey::from_json(&pk_json).expect("load pk");
    let hybrid_pk = pk_loaded.to_hybrid_public_key().expect("extract pk");

    let encrypted =
        encrypt(plaintext, EncryptKey::Hybrid(&hybrid_pk), CryptoConfig::new()).expect("encrypt");

    // Serialize EncryptedOutput to JSON (simulate writing to disk)
    let encrypted_json = serialize_encrypted_output(&encrypted).expect("serialize");
    drop(encrypted);
    drop(hybrid_pk);

    // === Process C: Load ONLY secret key from JSON, decrypt ===
    // No public key file needed — ML-KEM pk stored in secret key metadata
    let sk_loaded = PortableKey::from_json(&sk_json).expect("load sk");
    let hybrid_sk = sk_loaded.to_hybrid_secret_key().expect("reconstruct sk");

    let encrypted_loaded = deserialize_encrypted_output(&encrypted_json).expect("deserialize");
    let decrypted = decrypt(&encrypted_loaded, DecryptKey::Hybrid(&hybrid_sk), CryptoConfig::new())
        .expect("decrypt");

    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "Hybrid encrypt→serialize→deserialize→decrypt must match"
    );
}

// ============================================================================
// AAD Context Binding: encrypt with AAD → file → decrypt with same AAD
// ============================================================================

#[test]
fn roundtrip_aes_gcm_with_aad_through_file_succeeds() {
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

// ============================================================================
// 11. Signed Data Tamper Detection
// ============================================================================

#[test]
fn tamper_detection_modified_signed_data_fails() {
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
fn interop_simulation_sender_receiver_hybrid_succeeds() {
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

// ============================================================================
// 13. Double Serialization Stability
// ============================================================================

// ============================================================================
// 14. Concurrent File Access Pattern
// ============================================================================

// ============================================================================
// 15. Version/Format Forward Compatibility
// ============================================================================

// ============================================================================
// 16. Unicode and Special Content
// ============================================================================
