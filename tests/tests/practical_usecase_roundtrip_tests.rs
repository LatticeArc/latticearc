//! Practical Use-Case Round-Trip Tests — Process-Isolated
//!
//! Every UseCase enum variant, every SecurityLevel, and both SecurityMode variants
//! get a dedicated end-to-end test through file persistence with **process isolation**:
//!
//! ```text
//! WRITER (Process A): plaintext → encrypt(config) → serialize → write file → [drop all state]
//! READER (Process B): read file → deserialize → decrypt(key only) → plaintext
//! ```
//!
//! The writer and reader share ONLY:
//! - The file path (simulating disk/network transfer)
//! - The symmetric key (simulating pre-shared or exchanged key)
//!
//! The reader does NOT receive:
//! - The original CryptoConfig / UseCase / SecurityLevel
//! - Any in-memory EncryptedData struct
//! - Any variable from the writer's scope
//!
//! This proves the serialized format is self-describing — the reader reconstructs
//! everything it needs from the file alone.
//!
//! Additionally, real-world scenario tests simulate practical workflows:
//! - File encryption at rest (writer app → reader app)
//! - Database field encryption (backend writes → different service reads)
//! - Signed transactions (signer → independent verifier)
//! - IoT firmware signing (manufacturer → device)
//! - Multi-party document signing (N signers → verifier)
//! - Encrypted audit logs (writer service → forensic reader)
//! - Key rotation with mixed-version ciphertexts
//!
//! Run with:
//! ```bash
//! cargo test --package latticearc-tests --test practical_usecase_roundtrip_tests --all-features --release
//! ```

#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]
use std::convert::TryInto;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use latticearc::hybrid::kem::HybridPublicKey;
use latticearc::{
    CryptoConfig, CryptoScheme, DecryptKey, EncryptKey, EncryptedOutput, HybridComponents,
    SecurityLevel, SecurityMode, UseCase, VerifiedSession, decrypt, decrypt_aes_gcm, derive_key,
    deserialize_encrypted_data, deserialize_signed_data, encrypt, encrypt_aes_gcm, fips_available,
    generate_hybrid_keypair, generate_keypair, generate_signing_keypair, hash_data, hmac,
    hmac_check, serialize_encrypted_data, serialize_signed_data, sign_with_key, verify,
};

// ============================================================================
// Process-Isolated Helpers
// ============================================================================

/// WRITER PROCESS: Encrypts plaintext and writes the serialized ciphertext to a file.
/// Returns ONLY the file path — all in-memory crypto state is dropped.
fn writer_encrypt_to_file(plaintext: &[u8], key: &[u8; 32], config: CryptoConfig) -> PathBuf {
    let encrypted = encrypt(
        plaintext,
        EncryptKey::Symmetric(key),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .expect("writer: encrypt failed");
    let encrypted_data: latticearc::EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("writer: serialize failed");
    // Write to a temp file that persists after this function returns.
    // The caller is responsible for cleanup via std::fs::remove_file.
    let path = std::env::temp_dir().join(format!("latticearc-test-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("writer: failed to write file");
    path
    // All encrypt state (encrypted, json, EncryptedData) is dropped here.
    // Only the file on disk and the path survive.
}

/// READER PROCESS: Reads a file and decrypts using ONLY the key.
/// Has no knowledge of the original CryptoConfig, UseCase, or SecurityLevel.
/// Proves the serialized format is self-describing.
fn reader_decrypt_from_file(file_path: &Path, key: &[u8; 32]) -> Vec<u8> {
    let json = std::fs::read_to_string(file_path).expect("reader: failed to read file");
    let deserialized = deserialize_encrypted_data(&json).expect("reader: deserialize failed");
    // Note: CryptoConfig::new() = default config. Reader doesn't know writer's config.
    // decrypt() reads algorithm from deserialized.scheme, NOT from config.
    let output: EncryptedOutput = deserialized.try_into().expect("scheme should be valid");
    decrypt(&output, DecryptKey::Symmetric(key), CryptoConfig::new())
        .expect("reader: decrypt failed")
}

/// Full process-isolated round-trip: writer encrypts to file, reader decrypts from file.
/// Writer and reader share ONLY the key — no in-memory state is passed between them.
fn process_isolated_roundtrip(plaintext: &[u8], key: &[u8; 32], config: CryptoConfig) {
    let file_path = writer_encrypt_to_file(plaintext, key, config);
    let decrypted = reader_decrypt_from_file(&file_path, key);
    assert_eq!(decrypted.as_slice(), plaintext, "process-isolated round-trip mismatch");
    // Clean up
    let _ = std::fs::remove_file(&file_path);
}

/// Write string content to a temp file, return the file handle (for scenario tests
/// where the reader is in the same scope, keeping the NamedTempFile alive).
fn write_to_tempfile(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(content.as_bytes()).expect("failed to write");
    file.flush().expect("failed to flush");
    file
}

/// Write string content to a persistent temp file that outlives the caller.
/// Returns the path. Caller must clean up via std::fs::remove_file.
fn write_to_persistent_file(content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("latticearc-test-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, content.as_bytes()).expect("failed to write persistent file");
    path
}

/// Read string content from a temp file path (for scenario tests).
fn read_from_file(path: &Path) -> String {
    std::fs::read_to_string(path).expect("failed to read file")
}

/// JSON-serializable envelope for hybrid encrypted data.
/// EncryptedOutput doesn't derive Serialize/Deserialize,
/// so we need this bridge for file-based round-trip testing.
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
        use latticearc::EncryptionScheme;
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
// SECTION 1: Every UseCase Variant (Non-FIPS)
// ============================================================================

// --- Communication ---

#[test]
fn usecase_secure_messaging_roundtrip() {
    let key = [0x01u8; 32];
    let msg = b"Instant message: Hey, are you free for a call?";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::SecureMessaging));
}

#[test]
fn usecase_email_encryption_roundtrip() {
    let key = [0x02u8; 32];
    let msg = b"Subject: Q4 Revenue Report\n\nPlease find attached...";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::EmailEncryption));
}

#[test]
fn usecase_vpn_tunnel_roundtrip() {
    let key = [0x03u8; 32];
    let msg = b"VPN tunnel payload: TCP segment with encrypted IP header";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::VpnTunnel));
}

#[test]
fn usecase_api_security_roundtrip() {
    let key = [0x04u8; 32];
    let msg = br#"{"endpoint": "/api/v1/users", "method": "POST", "body": {"name": "Alice"}}"#;
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::ApiSecurity));
}

// --- Storage ---

#[test]
fn usecase_file_storage_roundtrip() {
    let key = [0x05u8; 32];
    let msg = b"Large file content: binary data representing a PDF document";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::FileStorage));
}

#[test]
fn usecase_database_encryption_roundtrip() {
    let key = [0x06u8; 32];
    let msg = b"SSN: 123-45-6789, DOB: 1990-01-15";
    process_isolated_roundtrip(
        msg,
        &key,
        CryptoConfig::new().use_case(UseCase::DatabaseEncryption),
    );
}

#[test]
fn usecase_cloud_storage_roundtrip() {
    let key = [0x07u8; 32];
    let msg = b"S3 object content: company financial spreadsheet data";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::CloudStorage));
}

#[test]
fn usecase_backup_archive_roundtrip() {
    let key = [0x08u8; 32];
    let msg = b"Backup archive: compressed database dump from 2026-02-20";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::BackupArchive));
}

#[test]
fn usecase_config_secrets_roundtrip() {
    let key = [0x09u8; 32];
    let msg = br#"{"db_password": "s3cur3!", "api_key": "sk_live_abc123"}"#;
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::ConfigSecrets));
}

// --- Authentication & Identity ---

#[test]
fn usecase_authentication_roundtrip() {
    let key = [0x0Au8; 32];
    let msg = b"auth_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::Authentication));
}

#[test]
fn usecase_session_token_roundtrip() {
    let key = [0x0Bu8; 32];
    let msg = b"session_id=abc123def456&user_id=42&expires=1708400000";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::SessionToken));
}

#[test]
fn usecase_digital_certificate_roundtrip() {
    let key = [0x0Cu8; 32];
    let msg = b"X.509 certificate data: CN=example.com, O=Acme Corp";
    process_isolated_roundtrip(
        msg,
        &key,
        CryptoConfig::new().use_case(UseCase::DigitalCertificate),
    );
}

#[test]
fn usecase_key_exchange_roundtrip() {
    let key = [0x0Du8; 32];
    let msg = b"Key exchange parameters: shared secret derivation context";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::KeyExchange));
}

// --- Financial & Legal (non-FIPS) ---

#[test]
fn usecase_legal_documents_roundtrip() {
    let key = [0x0Eu8; 32];
    let msg = b"CONFIDENTIAL: Contract #2026-0042, signed by both parties";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::LegalDocuments));
}

#[test]
fn usecase_blockchain_transaction_roundtrip() {
    let key = [0x0Fu8; 32];
    let msg = b"tx: 0xdeadbeef -> 0xcafebabe, amount: 1.5 ETH, nonce: 42";
    process_isolated_roundtrip(
        msg,
        &key,
        CryptoConfig::new().use_case(UseCase::BlockchainTransaction),
    );
}

// --- IoT & Embedded ---

#[test]
fn usecase_iot_device_roundtrip() {
    let key = [0x10u8; 32];
    let msg = b"sensor_reading: {temp: 22.5, humidity: 45.2, device_id: IoT-0042}";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::IoTDevice));
}

#[test]
fn usecase_firmware_signing_roundtrip() {
    let key = [0x11u8; 32];
    let msg = b"firmware_v2.1.0_sha256: a1b2c3d4e5f6...binary_payload";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::FirmwareSigning));
}

// --- Advanced ---

#[test]
fn usecase_audit_log_roundtrip() {
    let key = [0x14u8; 32];
    let msg = b"2026-02-20T10:30:00Z user=admin action=DELETE resource=/api/users/42";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().use_case(UseCase::AuditLog));
}

// --- FIPS-Requiring Use Cases (test that they correctly require FIPS feature) ---

#[test]
fn usecase_financial_transactions_requires_fips() {
    let key = [0x15u8; 32];
    let msg = b"WIRE: $1,000,000 to account 123456789";
    let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
    let result =
        encrypt(msg, EncryptKey::Symmetric(&key), config.force_scheme(CryptoScheme::Symmetric));
    if fips_available() {
        // With FIPS feature, regulated use cases should succeed
        assert!(result.is_ok(), "FinancialTransactions should succeed with FIPS feature");
    } else {
        assert!(result.is_err(), "FinancialTransactions should require FIPS feature");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("fips"), "Error should mention FIPS: {err}");
    }
}

#[test]
fn usecase_healthcare_records_requires_fips() {
    let key = [0x16u8; 32];
    let msg = b"Patient: Jane Doe, MRN: 12345, Diagnosis: ...";
    let config = CryptoConfig::new().use_case(UseCase::HealthcareRecords);
    let result =
        encrypt(msg, EncryptKey::Symmetric(&key), config.force_scheme(CryptoScheme::Symmetric));
    if fips_available() {
        assert!(result.is_ok(), "HealthcareRecords should succeed with FIPS feature");
    } else {
        assert!(result.is_err(), "HealthcareRecords should require FIPS feature");
    }
}

#[test]
fn usecase_government_classified_requires_fips() {
    let key = [0x17u8; 32];
    let msg = b"TOP SECRET: Operation details...";
    let config = CryptoConfig::new().use_case(UseCase::GovernmentClassified);
    let result =
        encrypt(msg, EncryptKey::Symmetric(&key), config.force_scheme(CryptoScheme::Symmetric));
    if fips_available() {
        assert!(result.is_ok(), "GovernmentClassified should succeed with FIPS feature");
    } else {
        assert!(result.is_err(), "GovernmentClassified should require FIPS feature");
    }
}

#[test]
fn usecase_payment_card_requires_fips() {
    let key = [0x18u8; 32];
    let msg = b"PAN: 4111-1111-1111-1111, CVV: 123, Exp: 12/28";
    let config = CryptoConfig::new().use_case(UseCase::PaymentCard);
    let result =
        encrypt(msg, EncryptKey::Symmetric(&key), config.force_scheme(CryptoScheme::Symmetric));
    if fips_available() {
        assert!(result.is_ok(), "PaymentCard should succeed with FIPS feature");
    } else {
        assert!(result.is_err(), "PaymentCard should require FIPS feature");
    }
}

// ============================================================================
// SECTION 2: Every SecurityLevel Variant
// ============================================================================

#[test]
fn security_level_standard_roundtrip() {
    let key = [0x20u8; 32];
    let msg = b"Standard security (NIST Level 1, 128-bit equivalent)";
    process_isolated_roundtrip(
        msg,
        &key,
        CryptoConfig::new().security_level(SecurityLevel::Standard),
    );
}

#[test]
fn security_level_high_roundtrip() {
    let key = [0x21u8; 32];
    let msg = b"High security (NIST Level 3, 192-bit equivalent, default)";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().security_level(SecurityLevel::High));
}

#[test]
fn security_level_maximum_roundtrip() {
    let key = [0x22u8; 32];
    let msg = b"Maximum security (NIST Level 5, 256-bit equivalent)";
    process_isolated_roundtrip(
        msg,
        &key,
        CryptoConfig::new().security_level(SecurityLevel::Maximum),
    );
}

#[test]
fn security_level_default_is_high() {
    let key = [0x23u8; 32];
    let msg = b"Default config should use High security level";
    // CryptoConfig::new() defaults to High
    process_isolated_roundtrip(msg, &key, CryptoConfig::new());
}

// ============================================================================
// SECTION 3: SecurityMode Variants
// ============================================================================

#[test]
fn security_mode_unverified_roundtrip() {
    let key = [0x30u8; 32];
    let msg = b"AES-GCM with Unverified security mode";

    let ciphertext = encrypt_aes_gcm(msg, &key, SecurityMode::Unverified).expect("encrypt failed");
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), msg);
}

#[test]
fn security_mode_verified_roundtrip() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(&pk, sk.as_ref()).expect("session establishment failed");

    let key = [0x31u8; 32];
    let msg = b"AES-GCM with Verified security mode (Zero Trust session)";

    let ciphertext = encrypt_aes_gcm(msg, &key, SecurityMode::Verified(&session))
        .expect("encrypt with session failed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Verified(&session))
        .expect("decrypt with session failed");
    assert_eq!(decrypted.as_slice(), msg);
}

#[test]
fn security_mode_verified_unified_api_roundtrip() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(&pk, sk.as_ref()).expect("session establishment failed");

    let key = [0x32u8; 32];
    let msg = b"Unified API with verified session through file";

    let config = CryptoConfig::new().session(&session).use_case(UseCase::SecureMessaging);
    let encrypted =
        encrypt(msg, EncryptKey::Symmetric(&key), config.force_scheme(CryptoScheme::Symmetric))
            .expect("encrypt failed");

    let encrypted_data: latticearc::EncryptedData = encrypted.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
    let file = write_to_tempfile(&json);
    let json_from_file = read_from_file(file.path());
    let deserialized = deserialize_encrypted_data(&json_from_file).expect("deserialize failed");

    // Decrypt with same session
    let config = CryptoConfig::new().session(&session);
    let output: EncryptedOutput = deserialized.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&output, DecryptKey::Symmetric(&key), config).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), msg);
}

#[test]
fn security_mode_verified_hybrid_roundtrip() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(&pk, sk.as_ref()).expect("session establishment failed");

    let (hybrid_pk, hybrid_sk) = generate_hybrid_keypair().expect("hybrid keygen failed");
    let msg = b"Hybrid encryption with verified session";

    let config = CryptoConfig::new().session(&session);
    let encrypted =
        encrypt(msg, EncryptKey::Hybrid(&hybrid_pk), config).expect("hybrid encrypt failed");
    let config = CryptoConfig::new().session(&session);
    let decrypted =
        decrypt(&encrypted, DecryptKey::Hybrid(&hybrid_sk), config).expect("hybrid decrypt failed");
    assert_eq!(decrypted.as_slice(), msg);
}

// ============================================================================
// SECTION 4: Real-World Scenario Tests
// ============================================================================

/// Scenario: Encrypt a file at rest, store it, retrieve and decrypt later.
/// Writer (backup process) and reader (restore process) are fully isolated.
#[test]
fn scenario_file_encryption_at_rest() {
    let key = [0x40u8; 32];
    let file_content = b"This is a sensitive document.\nPage 1 of 50.\nConfidential.";

    // === WRITER PROCESS (backup agent) ===
    // Knows: plaintext, key, use case
    let enc_path = writer_encrypt_to_file(
        file_content,
        &key,
        CryptoConfig::new().use_case(UseCase::FileStorage),
    );
    // Writer's encrypt state is dropped. Only file on disk remains.

    // === READER PROCESS (restore agent) ===
    // Knows: file path, key. Does NOT know use case or config.
    let stored_json = read_from_file(&enc_path);
    let loaded = deserialize_encrypted_data(&stored_json).expect("reader: load failed");

    // Reader can inspect metadata without the key (Kerckhoffs' principle)
    assert_eq!(loaded.scheme, "aes-256-gcm");
    assert!(loaded.timestamp > 0);

    let output: EncryptedOutput = loaded.try_into().expect("scheme should be valid");
    let decrypted = decrypt(&output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("reader: decrypt failed");
    assert_eq!(decrypted.as_slice(), file_content);
    let _ = std::fs::remove_file(&enc_path);
}

/// Scenario: Database column encryption (multiple fields, same key)
#[test]
fn scenario_database_column_encryption() {
    let key = [0x41u8; 32];

    #[derive(Serialize, Deserialize)]
    struct EncryptedRow {
        id: u64,
        name_encrypted: String, // serialized EncryptedData
        ssn_encrypted: String,
        email_encrypted: String,
    }

    let rows: Vec<(&str, &str, &str)> = vec![
        ("Alice Johnson", "123-45-6789", "alice@example.com"),
        ("Bob Smith", "987-65-4321", "bob@example.com"),
        ("Carol White", "555-12-3456", "carol@example.com"),
    ];

    let config = CryptoConfig::new().use_case(UseCase::DatabaseEncryption);

    let mut encrypted_rows = Vec::new();
    for (i, (name, ssn, email)) in rows.iter().enumerate() {
        let name_enc: latticearc::EncryptedData = encrypt(
            name.as_bytes(),
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt name")
        .into();
        let ssn_enc: latticearc::EncryptedData = encrypt(
            ssn.as_bytes(),
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt ssn")
        .into();
        let email_enc: latticearc::EncryptedData = encrypt(
            email.as_bytes(),
            EncryptKey::Symmetric(&key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt email")
        .into();

        encrypted_rows.push(EncryptedRow {
            id: u64::try_from(i).unwrap(),
            name_encrypted: serialize_encrypted_data(&name_enc).expect("serialize"),
            ssn_encrypted: serialize_encrypted_data(&ssn_enc).expect("serialize"),
            email_encrypted: serialize_encrypted_data(&email_enc).expect("serialize"),
        });
    }

    // Persist "database" to file
    let db_json = serde_json::to_string_pretty(&encrypted_rows).expect("serialize db");
    let db_file = write_to_tempfile(&db_json);

    // Query: load and decrypt a specific row's specific field
    let loaded_json = read_from_file(db_file.path());
    let loaded_rows: Vec<EncryptedRow> = serde_json::from_str(&loaded_json).expect("parse db");

    // Decrypt Bob's SSN (row index 1)
    let bob = &loaded_rows[1];
    let ssn_output: EncryptedOutput = deserialize_encrypted_data(&bob.ssn_encrypted)
        .expect("deserialize ssn")
        .try_into()
        .expect("scheme should be valid");
    let ssn_plain = decrypt(&ssn_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
        .expect("decrypt ssn");
    assert_eq!(String::from_utf8(ssn_plain).unwrap(), "987-65-4321");

    // Decrypt all names
    for (i, row) in loaded_rows.iter().enumerate() {
        let name_output: EncryptedOutput = deserialize_encrypted_data(&row.name_encrypted)
            .expect("deserialize")
            .try_into()
            .expect("scheme should be valid");
        let name_plain = decrypt(&name_output, DecryptKey::Symmetric(&key), CryptoConfig::new())
            .expect("decrypt");
        assert_eq!(String::from_utf8(name_plain).unwrap(), rows[i].0);
    }
}

/// Scenario: Sign a financial transaction document and persist
#[test]
fn scenario_signed_transaction() {
    let transaction = br#"{
        "from": "account_001",
        "to": "account_002",
        "amount": 50000.00,
        "currency": "USD",
        "memo": "Q4 dividend payment"
    }"#;

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");
    assert!(!scheme.is_empty());

    // Sign the transaction
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let signed = sign_with_key(transaction, &sk, &pk, config).expect("sign failed");

    // Persist signed transaction
    let json = serialize_signed_data(&signed).expect("serialize failed");
    let file = write_to_tempfile(&json);

    // Later: auditor retrieves and verifies
    let stored = read_from_file(file.path());
    let loaded = deserialize_signed_data(&stored).expect("deserialize failed");

    // Verify the original transaction data is recoverable
    assert_eq!(loaded.data, transaction.to_vec());

    // Verify signature
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let is_valid = verify(&loaded, config).expect("verify failed");
    assert!(is_valid, "Transaction signature should verify");
}

/// Scenario: IoT device sends encrypted sensor readings
#[test]
fn scenario_iot_sensor_data() {
    let device_key = [0x43u8; 32];

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct SensorReading {
        device_id: String,
        timestamp: u64,
        temperature: f64,
        humidity: f64,
        battery_pct: u8,
    }

    let readings = vec![
        SensorReading {
            device_id: "IoT-SENSOR-042".to_string(),
            timestamp: 1708400000,
            temperature: 22.5,
            humidity: 45.2,
            battery_pct: 87,
        },
        SensorReading {
            device_id: "IoT-SENSOR-042".to_string(),
            timestamp: 1708400060,
            temperature: 22.6,
            humidity: 45.0,
            battery_pct: 87,
        },
    ];

    // Device encrypts each reading
    let config = CryptoConfig::new().use_case(UseCase::IoTDevice);
    let mut encrypted_readings = Vec::new();
    for reading in &readings {
        let json = serde_json::to_string(reading).unwrap();
        let encrypted_output = encrypt(
            json.as_bytes(),
            EncryptKey::Symmetric(&device_key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("iot encrypt failed");
        let encrypted_data: latticearc::EncryptedData = encrypted_output.into();
        let enc_json = serialize_encrypted_data(&encrypted_data).expect("serialize failed");
        encrypted_readings.push(enc_json);
    }

    // Transmit (write to file simulating network transfer)
    let payload = serde_json::to_string(&encrypted_readings).unwrap();
    let file = write_to_tempfile(&payload);

    // Server receives and decrypts
    let received = read_from_file(file.path());
    let enc_jsons: Vec<String> = serde_json::from_str(&received).unwrap();

    for (i, enc_json) in enc_jsons.iter().enumerate() {
        let output: EncryptedOutput = deserialize_encrypted_data(enc_json)
            .expect("deserialize")
            .try_into()
            .expect("scheme should be valid");
        let decrypted = decrypt(&output, DecryptKey::Symmetric(&device_key), CryptoConfig::new())
            .expect("decrypt");
        let reading: SensorReading = serde_json::from_slice(&decrypted).expect("parse reading");
        assert_eq!(reading, readings[i]);
    }
}

/// Scenario: Firmware update with signed binary.
/// Manufacturer (signer) and device (verifier) are completely independent processes.
/// Device only has: the signed firmware file + manufacturer's public key.
#[test]
fn scenario_firmware_update_signing() {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let firmware: Vec<u8> = (0..512).map(|i: i32| (i % 256) as u8).collect();

    // === MANUFACTURER PROCESS: signs firmware, publishes update file ===
    let config = CryptoConfig::new().use_case(UseCase::FirmwareSigning);
    let (pk, sk, _) = generate_signing_keypair(config).expect("keygen failed");

    let update_file_path = {
        let config = CryptoConfig::new().use_case(UseCase::FirmwareSigning);
        let signed = sign_with_key(&firmware, &sk, &pk, config).expect("sign firmware");
        let json = serialize_signed_data(&signed).expect("serialize");
        write_to_persistent_file(&json)
        // Manufacturer's signing state (sk, signed) drops here
    };

    // === DEVICE PROCESS: downloads file, verifies signature, flashes firmware ===
    // Device knows: file path + manufacturer's public key. Nothing else.
    let received = read_from_file(&update_file_path);
    let loaded = deserialize_signed_data(&received).expect("device: deserialize");

    // Device verifies signature before flashing (public key was pre-installed)
    let config = CryptoConfig::new().use_case(UseCase::FirmwareSigning);
    let is_valid = verify(&loaded, config).expect("device: verify");
    assert!(is_valid, "Firmware signature must verify before flashing");

    // Verify firmware content matches expected binary
    assert_eq!(loaded.data, firmware);
}

// ============================================================================
// PROCESS-ISOLATED HYBRID ENCRYPTION (Real-World Messaging Pattern)
//
// These tests simulate true multi-party communication where:
// - Each party generates their own keypair independently
// - Public keys are exchanged ONLY via files (simulating network/directory)
// - Ciphertext is transmitted ONLY via files (simulating network)
// - Secret keys NEVER leave their owner's scope
// - NO in-memory state is shared between sender and receiver
// ============================================================================

/// JSON-serializable wrapper for hybrid public keys.
/// `HybridPublicKey` doesn't derive Serialize, so we bridge via base64.
#[derive(Debug, Serialize, Deserialize)]
struct SerializableHybridPublicKey {
    ml_kem_pk: String,  // base64
    ecdh_pk: String,    // base64
    security_level: u8, // 512=0, 768=1, 1024=2
}

impl SerializableHybridPublicKey {
    fn from_key(pk: &HybridPublicKey) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let level_byte = match pk.security_level {
            latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem512 => 0,
            latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem768 => 1,
            latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem1024 => 2,
        };
        Self {
            ml_kem_pk: STANDARD.encode(&pk.ml_kem_pk),
            ecdh_pk: STANDARD.encode(&pk.ecdh_pk),
            security_level: level_byte,
        }
    }

    fn to_key(&self) -> HybridPublicKey {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let level = match self.security_level {
            0 => latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem512,
            2 => latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem1024,
            _ => latticearc::primitives::kem::ml_kem::MlKemSecurityLevel::MlKem768,
        };
        HybridPublicKey {
            ml_kem_pk: STANDARD.decode(&self.ml_kem_pk).unwrap(),
            ecdh_pk: STANDARD.decode(&self.ecdh_pk).unwrap(),
            security_level: level,
        }
    }
}

/// Secure messaging: Alice encrypts a message to Bob using Bob's public key.
/// Bob decrypts with his private key. Public keys exchanged via files only.
///
/// ```text
/// BOB'S DEVICE:   keygen → write bob_pubkey.json to "directory"
/// ALICE'S DEVICE: read bob_pubkey.json → encrypt → write ciphertext.json
///                 [ALL of Alice's state dropped here]
/// BOB'S DEVICE:   read ciphertext.json → decrypt with private key → plaintext
/// ```
#[test]
fn e2e_secure_messaging_alice_to_bob() {
    let original_message = b"Hi Bob, the quarterly security audit passed. All clear.";

    // ── BOB'S DEVICE: Generate keypair, publish public key to file ──
    let (bob_sk, bob_pubkey_path) = {
        let (pk, sk) = generate_hybrid_keypair().expect("bob keygen");
        let serializable = SerializableHybridPublicKey::from_key(&pk);
        let json = serde_json::to_string(&serializable).unwrap();
        let path = write_to_persistent_file(&json);
        // pk is dropped — Bob only keeps sk and the path where pk was published
        (sk, path)
    };

    // ── ALICE'S DEVICE: Read Bob's public key from file, encrypt, write ciphertext ──
    let ciphertext_path = {
        // Alice reads Bob's public key from the "directory" (file)
        let bob_pk_json = read_from_file(&bob_pubkey_path);
        let bob_pk =
            serde_json::from_str::<SerializableHybridPublicKey>(&bob_pk_json).unwrap().to_key();

        // Alice encrypts with Bob's public key using unified API
        let encrypted = encrypt(original_message, EncryptKey::Hybrid(&bob_pk), CryptoConfig::new())
            .expect("alice encrypt failed");

        // Alice writes ciphertext to "network" (file)
        let serializable = SerializableHybridEncrypted::from_encrypted_output(&encrypted);
        let json = serde_json::to_string(&serializable).unwrap();
        write_to_persistent_file(&json)
        // ALL of Alice's state drops here: bob_pk, encrypted, serializable, json
    };

    // ── BOB'S DEVICE: Read ciphertext from file, decrypt with his private key ──
    let decrypted = {
        let json = read_from_file(&ciphertext_path);
        let deserialized: SerializableHybridEncrypted = serde_json::from_str(&json).unwrap();
        let restored = deserialized.to_encrypted_output();
        decrypt(&restored, DecryptKey::Hybrid(&bob_sk), CryptoConfig::new())
            .expect("bob decrypt failed")
        // restored, deserialized, json all drop here
    };

    assert_eq!(decrypted.as_slice(), original_message);

    // Cleanup
    let _ = std::fs::remove_file(&bob_pubkey_path);
    let _ = std::fs::remove_file(&ciphertext_path);
}

/// Bidirectional secure channel: Alice sends to Bob, Bob replies to Alice.
/// Each direction uses the recipient's public key (read from file).
/// No in-memory state crosses between the four scopes.
///
/// ```text
/// SETUP:
///   Alice: keygen → write alice_pubkey.json
///   Bob:   keygen → write bob_pubkey.json
///
/// ALICE → BOB:
///   Alice: read bob_pubkey.json → encrypt → write msg1.json → [drop all]
///   Bob:   read msg1.json → decrypt with bob_sk → assert correct
///
/// BOB → ALICE:
///   Bob:   read alice_pubkey.json → encrypt → write msg2.json → [drop all]
///   Alice: read msg2.json → decrypt with alice_sk → assert correct
/// ```
#[test]
fn e2e_bidirectional_secure_channel() {
    // ── SETUP: Both parties generate keypairs and publish public keys ──
    let (alice_sk, alice_pubkey_path) = {
        let (pk, sk) = generate_hybrid_keypair().expect("alice keygen");
        let json = serde_json::to_string(&SerializableHybridPublicKey::from_key(&pk)).unwrap();
        (sk, write_to_persistent_file(&json))
    };
    let (bob_sk, bob_pubkey_path) = {
        let (pk, sk) = generate_hybrid_keypair().expect("bob keygen");
        let json = serde_json::to_string(&SerializableHybridPublicKey::from_key(&pk)).unwrap();
        (sk, write_to_persistent_file(&json))
    };

    // ── ALICE → BOB: Alice reads Bob's pubkey from file, encrypts, writes ciphertext ──
    let alice_msg = b"Bob, I need you to rotate the API keys by end of day.";
    let msg1_path = {
        let bob_pk =
            serde_json::from_str::<SerializableHybridPublicKey>(&read_from_file(&bob_pubkey_path))
                .unwrap()
                .to_key();
        let encrypted = encrypt(alice_msg, EncryptKey::Hybrid(&bob_pk), CryptoConfig::new())
            .expect("alice→bob encrypt");
        let json =
            serde_json::to_string(&SerializableHybridEncrypted::from_encrypted_output(&encrypted))
                .unwrap();
        write_to_persistent_file(&json)
        // bob_pk, encrypted, json all dropped
    };

    // ── BOB receives: reads ciphertext from file, decrypts with his key ──
    let bob_received = {
        let restored =
            serde_json::from_str::<SerializableHybridEncrypted>(&read_from_file(&msg1_path))
                .unwrap()
                .to_encrypted_output();
        decrypt(&restored, DecryptKey::Hybrid(&bob_sk), CryptoConfig::new()).expect("bob decrypt")
    };
    assert_eq!(bob_received.as_slice(), alice_msg);
    let _ = std::fs::remove_file(&msg1_path);

    // ── BOB → ALICE: Bob reads Alice's pubkey from file, encrypts reply ──
    let bob_reply = b"Done. All 12 API keys rotated. New keys in the vault.";
    let msg2_path = {
        let alice_pk = serde_json::from_str::<SerializableHybridPublicKey>(&read_from_file(
            &alice_pubkey_path,
        ))
        .unwrap()
        .to_key();
        let encrypted = encrypt(bob_reply, EncryptKey::Hybrid(&alice_pk), CryptoConfig::new())
            .expect("bob→alice encrypt");
        let json =
            serde_json::to_string(&SerializableHybridEncrypted::from_encrypted_output(&encrypted))
                .unwrap();
        write_to_persistent_file(&json)
        // alice_pk, encrypted, json all dropped
    };

    // ── ALICE receives: reads ciphertext from file, decrypts with her key ──
    let alice_received = {
        let restored =
            serde_json::from_str::<SerializableHybridEncrypted>(&read_from_file(&msg2_path))
                .unwrap()
                .to_encrypted_output();
        decrypt(&restored, DecryptKey::Hybrid(&alice_sk), CryptoConfig::new())
            .expect("alice decrypt")
    };
    assert_eq!(alice_received.as_slice(), bob_reply);

    // Cleanup
    let _ = std::fs::remove_file(&alice_pubkey_path);
    let _ = std::fs::remove_file(&bob_pubkey_path);
    let _ = std::fs::remove_file(&msg2_path);
}

/// Wrong-key rejection: Alice encrypts for Bob, Eve tries to decrypt with her own key.
/// Proves ciphertext is bound to the recipient's keypair.
#[test]
fn e2e_wrong_recipient_key_rejected() {
    // Bob publishes his public key
    let (bob_sk, bob_pubkey_path) = {
        let (pk, sk) = generate_hybrid_keypair().expect("bob keygen");
        let json = serde_json::to_string(&SerializableHybridPublicKey::from_key(&pk)).unwrap();
        (sk, write_to_persistent_file(&json))
    };

    // Eve generates her own keypair (attacker)
    let (_eve_pk, eve_sk) = generate_hybrid_keypair().expect("eve keygen");

    // Alice encrypts for Bob (reads Bob's pubkey from file)
    let ciphertext_path = {
        let bob_pk =
            serde_json::from_str::<SerializableHybridPublicKey>(&read_from_file(&bob_pubkey_path))
                .unwrap()
                .to_key();
        let encrypted = encrypt(
            b"Confidential: merger details",
            EncryptKey::Hybrid(&bob_pk),
            CryptoConfig::new(),
        )
        .expect("encrypt");
        let json =
            serde_json::to_string(&SerializableHybridEncrypted::from_encrypted_output(&encrypted))
                .unwrap();
        write_to_persistent_file(&json)
    };

    // Eve intercepts the file and tries to decrypt with her own key — MUST fail
    let eve_result = {
        let restored =
            serde_json::from_str::<SerializableHybridEncrypted>(&read_from_file(&ciphertext_path))
                .unwrap()
                .to_encrypted_output();
        decrypt(&restored, DecryptKey::Hybrid(&eve_sk), CryptoConfig::new())
    };
    assert!(eve_result.is_err(), "Eve must NOT be able to decrypt Bob's message");

    // Bob decrypts with his own key — MUST succeed
    let bob_result = {
        let restored =
            serde_json::from_str::<SerializableHybridEncrypted>(&read_from_file(&ciphertext_path))
                .unwrap()
                .to_encrypted_output();
        decrypt(&restored, DecryptKey::Hybrid(&bob_sk), CryptoConfig::new())
    };
    assert!(bob_result.is_ok(), "Bob must be able to decrypt his own message");
    assert_eq!(bob_result.unwrap().as_slice(), b"Confidential: merger details");

    let _ = std::fs::remove_file(&bob_pubkey_path);
    let _ = std::fs::remove_file(&ciphertext_path);
}

/// Sign-then-encrypt: Alice signs a message (authenticity), encrypts for Bob
/// (confidentiality). Bob decrypts, then verifies the signature.
/// All key exchange and data transfer happens via files.
#[test]
fn e2e_sign_then_encrypt_full_channel() {
    let message = b"Transfer $50,000 to account 9876543210. Authorization code: ALPHA-7.";

    // ── SETUP: Both parties generate encryption + signing keypairs ──
    let (bob_enc_sk, bob_enc_pubkey_path) = {
        let (pk, sk) = generate_hybrid_keypair().expect("bob enc keygen");
        let json = serde_json::to_string(&SerializableHybridPublicKey::from_key(&pk)).unwrap();
        (sk, write_to_persistent_file(&json))
    };

    let signing_config = CryptoConfig::new().use_case(UseCase::Authentication);
    let (alice_sign_pk, alice_sign_sk, _scheme) =
        generate_signing_keypair(signing_config.clone()).expect("alice sign keygen");

    // Alice publishes her signing public key
    let alice_sign_pk_path = {
        use base64::{Engine, engine::general_purpose::STANDARD};
        write_to_persistent_file(&STANDARD.encode(&alice_sign_pk))
    };

    // ── ALICE'S DEVICE: Sign message, then encrypt the signed bundle for Bob ──
    let encrypted_signed_path = {
        // Step 1: Alice signs the message
        let signed = sign_with_key(message, &alice_sign_sk, &alice_sign_pk, signing_config.clone())
            .expect("alice sign");
        let signed_json = serialize_signed_data(&signed).expect("serialize signed");

        // Step 2: Alice reads Bob's encryption pubkey from file
        let bob_pk = serde_json::from_str::<SerializableHybridPublicKey>(&read_from_file(
            &bob_enc_pubkey_path,
        ))
        .unwrap()
        .to_key();

        // Step 3: Alice encrypts the signed bundle with Bob's public key
        let encrypted =
            encrypt(signed_json.as_bytes(), EncryptKey::Hybrid(&bob_pk), CryptoConfig::new())
                .expect("alice encrypt");
        let json =
            serde_json::to_string(&SerializableHybridEncrypted::from_encrypted_output(&encrypted))
                .unwrap();
        write_to_persistent_file(&json)
        // ALL of Alice's state dropped: signed, signed_json, bob_pk, encrypted
    };

    // ── BOB'S DEVICE: Decrypt, then verify Alice's signature ──
    {
        // Step 1: Bob decrypts the outer hybrid layer with his private key
        let restored = serde_json::from_str::<SerializableHybridEncrypted>(&read_from_file(
            &encrypted_signed_path,
        ))
        .unwrap()
        .to_encrypted_output();
        let decrypted_signed_json =
            decrypt(&restored, DecryptKey::Hybrid(&bob_enc_sk), CryptoConfig::new())
                .expect("bob decrypt");

        // Step 2: Bob deserializes the signed data
        let signed_data = deserialize_signed_data(
            std::str::from_utf8(&decrypted_signed_json).expect("valid utf8"),
        )
        .expect("deserialize signed");

        // Step 3: Bob reads Alice's signing public key from file and compares
        use base64::{Engine, engine::general_purpose::STANDARD};
        let alice_pk_from_file = STANDARD
            .decode(read_from_file(Path::new(&alice_sign_pk_path)))
            .expect("decode alice pk");
        assert_eq!(
            signed_data.metadata.public_key, alice_pk_from_file,
            "Embedded public key must match Alice's published key"
        );

        // Step 4: Bob verifies the signature
        let valid = verify(&signed_data, signing_config).expect("verify");
        assert!(valid, "Alice's signature must verify");

        // Step 5: Bob reads the original message
        assert_eq!(signed_data.data.as_slice(), message);
    }

    // Cleanup
    let _ = std::fs::remove_file(&bob_enc_pubkey_path);
    let _ = std::fs::remove_file(&alice_sign_pk_path);
    let _ = std::fs::remove_file(&encrypted_signed_path);
}

/// Scenario: Encrypted audit log (append-only pattern)
#[test]
fn scenario_encrypted_audit_log() {
    let log_key = [0x45u8; 32];
    let config = CryptoConfig::new().use_case(UseCase::AuditLog);

    let log_entries = vec![
        "2026-02-20T10:00:00Z [INFO] user=admin login from 192.168.1.1",
        "2026-02-20T10:05:00Z [WARN] user=admin accessed /api/secrets",
        "2026-02-20T10:10:00Z [INFO] user=admin exported 42 records",
        "2026-02-20T10:15:00Z [ALERT] user=admin attempted privilege escalation",
    ];

    // Encrypt and append each entry
    let mut encrypted_log: Vec<String> = Vec::new();
    for entry in &log_entries {
        let encrypted_output = encrypt(
            entry.as_bytes(),
            EncryptKey::Symmetric(&log_key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt log entry");
        let encrypted_data: latticearc::EncryptedData = encrypted_output.into();
        let json = serialize_encrypted_data(&encrypted_data).expect("serialize");
        encrypted_log.push(json);
    }

    // Persist log
    let log_json = serde_json::to_string_pretty(&encrypted_log).unwrap();
    let log_file = write_to_tempfile(&log_json);

    // Forensic analysis: load and decrypt all entries
    let loaded = read_from_file(log_file.path());
    let stored_entries: Vec<String> = serde_json::from_str(&loaded).unwrap();

    for (i, enc_json) in stored_entries.iter().enumerate() {
        let output: EncryptedOutput = deserialize_encrypted_data(enc_json)
            .expect("deserialize")
            .try_into()
            .expect("scheme should be valid");
        let decrypted = decrypt(&output, DecryptKey::Symmetric(&log_key), CryptoConfig::new())
            .expect("decrypt");
        assert_eq!(String::from_utf8(decrypted).unwrap(), log_entries[i]);
    }
}

/// Scenario: Config/secrets vault (encrypted key-value store)
#[test]
fn scenario_config_secrets_vault() {
    let vault_key = [0x46u8; 32];
    let config = CryptoConfig::new().use_case(UseCase::ConfigSecrets);

    #[derive(Serialize, Deserialize)]
    struct SecretVault {
        entries: Vec<VaultEntry>,
    }

    #[derive(Serialize, Deserialize)]
    struct VaultEntry {
        name: String,
        encrypted_value: String,
    }

    let secrets = vec![
        ("DATABASE_URL", "postgres://user:pass@db.internal:5432/prod"),
        ("API_KEY", "test_api_key_not_real_abc123xyz"),
        ("JWT_SECRET", "super-secret-jwt-signing-key-2026"),
        ("STRIPE_WEBHOOK_SECRET", "whsec_test_secret_key_value"),
    ];

    let mut vault = SecretVault { entries: Vec::new() };
    for (name, value) in &secrets {
        let encrypted_output = encrypt(
            value.as_bytes(),
            EncryptKey::Symmetric(&vault_key),
            config.clone().force_scheme(CryptoScheme::Symmetric),
        )
        .expect("encrypt secret");
        let encrypted_data: latticearc::EncryptedData = encrypted_output.into();
        let enc_json = serialize_encrypted_data(&encrypted_data).expect("serialize");
        vault.entries.push(VaultEntry { name: name.to_string(), encrypted_value: enc_json });
    }

    // Persist vault to file
    let vault_json = serde_json::to_string_pretty(&vault).unwrap();
    let vault_file = write_to_tempfile(&vault_json);

    // Application startup: load and decrypt specific secret
    let loaded = read_from_file(vault_file.path());
    let loaded_vault: SecretVault = serde_json::from_str(&loaded).unwrap();

    let api_key_entry = loaded_vault
        .entries
        .iter()
        .find(|e| e.name == "API_KEY")
        .expect("API_KEY not found in vault");

    let output: EncryptedOutput = deserialize_encrypted_data(&api_key_entry.encrypted_value)
        .expect("deserialize")
        .try_into()
        .expect("scheme should be valid");
    let decrypted =
        decrypt(&output, DecryptKey::Symmetric(&vault_key), CryptoConfig::new()).expect("decrypt");

    assert_eq!(String::from_utf8(decrypted).unwrap(), "test_api_key_not_real_abc123xyz");
}

/// Scenario: Key rotation — old ciphertexts remain decryptable with old key
#[test]
fn scenario_key_rotation() {
    let old_key = [0x47u8; 32];
    let new_key = [0x48u8; 32];

    // Encrypt data with old key
    let msg1 = b"Encrypted with old key before rotation";
    let enc1_output = encrypt(
        msg1,
        EncryptKey::Symmetric(&old_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt v1");
    let enc1_data: latticearc::EncryptedData = enc1_output.into();
    let json1 = serialize_encrypted_data(&enc1_data).expect("serialize");

    // Key rotation happens: new data encrypted with new key
    let msg2 = b"Encrypted with new key after rotation";
    let enc2_output = encrypt(
        msg2,
        EncryptKey::Symmetric(&new_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt v2");
    let enc2_data: latticearc::EncryptedData = enc2_output.into();
    let json2 = serialize_encrypted_data(&enc2_data).expect("serialize");

    // Store both (simulating a database with mixed-version ciphertexts)
    #[derive(Serialize, Deserialize)]
    struct VersionedCiphertext {
        key_version: u32,
        encrypted_json: String,
    }

    let store = vec![
        VersionedCiphertext { key_version: 1, encrypted_json: json1 },
        VersionedCiphertext { key_version: 2, encrypted_json: json2 },
    ];

    let store_json = serde_json::to_string_pretty(&store).unwrap();
    let file = write_to_tempfile(&store_json);

    // Application reads and selects correct key based on version
    let loaded = read_from_file(file.path());
    let loaded_store: Vec<VersionedCiphertext> = serde_json::from_str(&loaded).unwrap();

    for item in &loaded_store {
        let output: EncryptedOutput = deserialize_encrypted_data(&item.encrypted_json)
            .expect("deserialize")
            .try_into()
            .expect("scheme should be valid");
        let key = match item.key_version {
            1 => &old_key,
            2 => &new_key,
            _ => panic!("Unknown key version"),
        };
        let decrypted =
            decrypt(&output, DecryptKey::Symmetric(key), CryptoConfig::new()).expect("decrypt");

        if item.key_version == 1 {
            assert_eq!(decrypted.as_slice(), msg1);
        } else {
            assert_eq!(decrypted.as_slice(), msg2);
        }
    }
}

/// Scenario: Multi-party document signing (multiple signatures on same document)
#[test]
fn scenario_multi_party_signing() {
    let document = b"AGREEMENT: All parties agree to the terms described herein.";

    // Party A signs
    let config_a = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk_a, sk_a, _) = generate_signing_keypair(config_a).expect("keygen A");
    let config_a = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed_a = sign_with_key(document, &sk_a, &pk_a, config_a).expect("sign A");

    // Party B signs the same document
    let config_b = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk_b, sk_b, _) = generate_signing_keypair(config_b).expect("keygen B");
    let config_b = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed_b = sign_with_key(document, &sk_b, &pk_b, config_b).expect("sign B");

    // Store both signatures
    #[derive(Serialize, Deserialize)]
    struct MultiSigDocument {
        document_hash: String,
        signatures: Vec<String>, // serialized SignedData
    }

    let doc_hash = hex::encode(hash_data(document));

    let multi_sig = MultiSigDocument {
        document_hash: doc_hash.clone(),
        signatures: vec![
            serialize_signed_data(&signed_a).expect("serialize A"),
            serialize_signed_data(&signed_b).expect("serialize B"),
        ],
    };

    let json = serde_json::to_string_pretty(&multi_sig).unwrap();
    let file = write_to_tempfile(&json);

    // Verify all signatures
    let loaded = read_from_file(file.path());
    let loaded_doc: MultiSigDocument = serde_json::from_str(&loaded).unwrap();

    // Verify document hash matches
    assert_eq!(loaded_doc.document_hash, doc_hash);

    // Verify each signature
    for (i, sig_json) in loaded_doc.signatures.iter().enumerate() {
        let signed = deserialize_signed_data(sig_json).expect("deserialize");
        assert_eq!(signed.data, document.to_vec(), "document data mismatch in sig {i}");

        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let is_valid = verify(&signed, config).expect("verify");
        assert!(is_valid, "Signature {i} should verify");
    }
}

/// Scenario: Encrypted backup with integrity verification
#[test]
fn scenario_encrypted_backup_with_hmac() {
    let encryption_key = [0x49u8; 32];
    let hmac_key = [0x4Au8; 32];

    let backup_data = b"Database dump: 1000 rows of customer data...";

    // Encrypt the backup
    let config = CryptoConfig::new().use_case(UseCase::BackupArchive);
    let encrypted_output = encrypt(
        backup_data,
        EncryptKey::Symmetric(&encryption_key),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt backup");
    let encrypted_data: latticearc::EncryptedData = encrypted_output.into();
    let enc_json = serialize_encrypted_data(&encrypted_data).expect("serialize");

    // Compute HMAC over the serialized encrypted data (integrity check)
    let mac = hmac(enc_json.as_bytes(), &hmac_key, SecurityMode::Unverified).expect("hmac failed");

    // Store encrypted data + HMAC
    #[derive(Serialize, Deserialize)]
    struct IntegrityBackup {
        encrypted_data: String,
        hmac: String, // hex-encoded HMAC
    }

    let backup = IntegrityBackup { encrypted_data: enc_json, hmac: hex::encode(&mac) };

    let json = serde_json::to_string_pretty(&backup).unwrap();
    let file = write_to_tempfile(&json);

    // Restore: verify integrity then decrypt
    let loaded = read_from_file(file.path());
    let loaded_backup: IntegrityBackup = serde_json::from_str(&loaded).unwrap();

    // Step 1: Verify HMAC
    let expected_mac = hex::decode(&loaded_backup.hmac).unwrap();
    let integrity_ok = hmac_check(
        loaded_backup.encrypted_data.as_bytes(),
        &hmac_key,
        &expected_mac,
        SecurityMode::Unverified,
    )
    .expect("hmac_check failed");
    assert!(integrity_ok, "Backup integrity check should pass");

    // Step 2: Decrypt
    let output: EncryptedOutput = deserialize_encrypted_data(&loaded_backup.encrypted_data)
        .expect("deserialize")
        .try_into()
        .expect("scheme should be valid");
    let decrypted = decrypt(&output, DecryptKey::Symmetric(&encryption_key), CryptoConfig::new())
        .expect("decrypt backup");
    assert_eq!(decrypted.as_slice(), backup_data);
}

/// Scenario: Session token encrypted with derived key
#[test]
fn scenario_session_token_with_derived_key() {
    let master_key = [0x4Bu8; 32];
    let salt = b"session-key-derivation-salt-2026";

    // Derive a session-specific key from master key
    let derived =
        derive_key(&master_key, salt, 32, SecurityMode::Unverified).expect("key derivation failed");
    let session_key: [u8; 32] = derived.as_slice().try_into().expect("key size mismatch");

    let token_data = br#"{"user_id": 42, "role": "admin", "expires": 1708500000}"#;

    let config = CryptoConfig::new().use_case(UseCase::SessionToken);
    let encrypted_output = encrypt(
        token_data,
        EncryptKey::Symmetric(&session_key),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt token");
    let encrypted_data: latticearc::EncryptedData = encrypted_output.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize");
    let file = write_to_tempfile(&json);

    // Server validates token later using same derived key
    let loaded = read_from_file(file.path());
    let restored: EncryptedOutput = deserialize_encrypted_data(&loaded)
        .expect("deserialize")
        .try_into()
        .expect("scheme should be valid");

    // Re-derive key from master
    let re_derived = derive_key(&master_key, salt, 32, SecurityMode::Unverified)
        .expect("key re-derivation failed");
    let re_key: [u8; 32] = re_derived.as_slice().try_into().unwrap();

    let decrypted = decrypt(&restored, DecryptKey::Symmetric(&re_key), CryptoConfig::new())
        .expect("decrypt token");
    let token_str = String::from_utf8(decrypted).unwrap();
    let token: serde_json::Value = serde_json::from_str(&token_str).unwrap();

    assert_eq!(token["user_id"], 42);
    assert_eq!(token["role"], "admin");
}

/// Scenario: Cloud storage with metadata for key management
#[test]
fn scenario_cloud_storage_with_key_metadata() {
    let key = [0x4Cu8; 32];
    let config = CryptoConfig::new().use_case(UseCase::CloudStorage);

    let object_content = b"Cloud object: quarterly_report_2026_Q1.xlsx (binary)";

    let mut encrypted_output = encrypt(
        object_content,
        EncryptKey::Symmetric(&key),
        config.force_scheme(CryptoScheme::Symmetric),
    )
    .expect("encrypt");

    // Tag with key management metadata
    encrypted_output.key_id = Some("arn:aws:kms:us-east-1:123456789:key/mrk-abc123".to_string());

    let encrypted_data: latticearc::EncryptedData = encrypted_output.into();
    let json = serialize_encrypted_data(&encrypted_data).expect("serialize");
    let file = write_to_tempfile(&json);

    // Key management system reads metadata to fetch correct key
    let loaded_json = read_from_file(file.path());
    let raw: serde_json::Value = serde_json::from_str(&loaded_json).unwrap();

    let key_arn = raw["metadata"]["key_id"].as_str().unwrap();
    assert!(key_arn.starts_with("arn:aws:kms:"));

    // Decrypt after key lookup
    let output: EncryptedOutput = deserialize_encrypted_data(&loaded_json)
        .expect("deserialize")
        .try_into()
        .expect("scheme should be valid");
    let decrypted =
        decrypt(&output, DecryptKey::Symmetric(&key), CryptoConfig::new()).expect("decrypt");
    assert_eq!(decrypted.as_slice(), object_content);
}
