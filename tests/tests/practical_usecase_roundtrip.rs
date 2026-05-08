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
//! The reader does NOT receive the original CryptoConfig / UseCase / SecurityLevel,
//! or any variable from the writer's scope. This proves the serialized format is
//! self-describing — the reader reconstructs everything it needs from the file alone.
//!
//! Run with:
//! ```bash
//! cargo test --package latticearc-tests --test practical_usecase_roundtrip --all-features --release
//! ```

#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unreachable)]
#![allow(clippy::indexing_slicing)]
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use latticearc::hybrid::HybridKemPublicKey;
use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use latticearc::{
    ComplianceMode, CryptoConfig, CryptoScheme, DecryptKey, EncryptKey, EncryptedOutput,
    EncryptionScheme, HybridComponents, SecurityLevel, SecurityMode, UseCase, VerifiedSession,
    decrypt, decrypt_aes_gcm, decrypt_aes_gcm_with_aad, deserialize_encrypted_output,
    deserialize_signed_data, encrypt, encrypt_aes_gcm, encrypt_aes_gcm_with_aad, fips_available,
    generate_hybrid_keypair, generate_hybrid_keypair_with_level, generate_keypair,
    generate_signing_keypair, hash_data, serialize_encrypted_output, serialize_signed_data,
    sign_with_key, verify,
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
    let json = serialize_encrypted_output(&encrypted).expect("writer: serialize failed");
    let path = std::env::temp_dir().join(format!("latticearc-test-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("writer: failed to write file");
    path
}

/// READER PROCESS: Reads a file and decrypts using ONLY the key.
/// Has no knowledge of the original CryptoConfig, UseCase, or SecurityLevel.
/// Proves the serialized format is self-describing.
fn reader_decrypt_from_file(file_path: &Path, key: &[u8; 32]) -> Vec<u8> {
    let json = std::fs::read_to_string(file_path).expect("reader: failed to read file");
    let output = deserialize_encrypted_output(&json).expect("reader: deserialize failed");
    decrypt(&output, DecryptKey::Symmetric(key), CryptoConfig::new())
        .expect("reader: decrypt failed")
        .to_vec()
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
        use latticearc::EncryptionScheme;
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
        .expect("hybrid scheme + populated hybrid_data is a valid shape")
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
fn usecase_financial_transactions_requires_fips_succeeds() {
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
fn usecase_healthcare_records_requires_fips_succeeds() {
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
fn usecase_government_classified_requires_fips_succeeds() {
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
fn usecase_payment_card_requires_fips_succeeds() {
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
fn security_level_maximum_pq_only_roundtrip() {
    let key = [0x24u8; 32];
    let msg = b"Maximum+PqOnly security (CNSA 2.0 eligible)";
    process_isolated_roundtrip(
        msg,
        &key,
        CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .crypto_mode(latticearc::CryptoMode::PqOnly),
    );
}

#[test]
fn security_level_default_is_high_verified() {
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
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())
        .expect("session establishment failed");

    let key = [0x31u8; 32];
    let msg = b"AES-GCM with Verified security mode (Zero Trust session)";

    let ciphertext = encrypt_aes_gcm(msg, &key, SecurityMode::Verified(&session))
        .expect("encrypt with session failed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Verified(&session))
        .expect("decrypt with session failed");
    assert_eq!(decrypted.as_slice(), msg);
}

#[test]
fn security_mode_verified_hybrid_roundtrip() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())
        .expect("session establishment failed");

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
/// Scenario: Database column encryption (multiple fields, same key)
/// Scenario: Sign a financial transaction document and persist
#[test]
fn scenario_signed_transaction_succeeds() {
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
/// Scenario: Firmware update with signed binary.
/// Manufacturer (signer) and device (verifier) are completely independent processes.
/// Device only has: the signed firmware file + manufacturer's public key.
#[test]
fn scenario_firmware_update_signing_succeeds() {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test/bench scaffolding: lints suppressed for this module"
    )]
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
    fn from_key(pk: &HybridKemPublicKey) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let level_byte = match pk.security_level() {
            MlKemSecurityLevel::MlKem512 => 0,
            MlKemSecurityLevel::MlKem768 => 1,
            MlKemSecurityLevel::MlKem1024 => 2,
            _ => unreachable!("unexpected MlKemSecurityLevel variant"),
        };
        Self {
            ml_kem_pk: STANDARD.encode(pk.ml_kem_pk()),
            ecdh_pk: STANDARD.encode(pk.ecdh_pk()),
            security_level: level_byte,
        }
    }

    fn to_key(&self) -> HybridKemPublicKey {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let level = match self.security_level {
            0 => MlKemSecurityLevel::MlKem512,
            2 => MlKemSecurityLevel::MlKem1024,
            _ => MlKemSecurityLevel::MlKem768,
        };
        HybridKemPublicKey::new(
            STANDARD.decode(&self.ml_kem_pk).unwrap(),
            STANDARD.decode(&self.ecdh_pk).unwrap(),
            level,
        )
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
fn e2e_secure_messaging_alice_to_bob_succeeds() {
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
fn e2e_bidirectional_secure_channel_succeeds() {
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
fn e2e_sign_then_encrypt_full_channel_succeeds() {
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
/// Scenario: Config/secrets vault (encrypted key-value store)
/// Scenario: Key rotation — old ciphertexts remain decryptable with old key
/// Scenario: Multi-party document signing (multiple signatures on same document)
#[test]
fn scenario_multi_party_signing_succeeds() {
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

// ============================================================================
// SECTION 5: VerifiedSession × UseCase × SecurityLevel
//
// Tests that a VerifiedSession can drive encrypt → file → decrypt roundtrips
// for multiple UseCases and SecurityLevels (not just SecureMessaging).
// ============================================================================

/// Helper: establish a VerifiedSession, encrypt with (session + use_case),
/// write to file, read back, decrypt with session — process-isolated.
fn verified_session_usecase_roundtrip(use_case: UseCase) {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session failed");
    let key = [0x50u8; 32];
    let msg = format!("VerifiedSession + UseCase::{use_case:?}");

    let config = CryptoConfig::new()
        .session(&session)
        .use_case(use_case)
        .force_scheme(CryptoScheme::Symmetric);
    let encrypted =
        encrypt(msg.as_bytes(), EncryptKey::Symmetric(&key), config).expect("encrypt failed");
    let json = serialize_encrypted_output(&encrypted).expect("serialize failed");
    let path = std::env::temp_dir().join(format!("latticearc-vs-uc-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("write failed");

    // Reader: only has file + key + session
    let json_read = std::fs::read_to_string(&path).expect("read failed");
    let output = deserialize_encrypted_output(&json_read).expect("deserialize failed");
    let config = CryptoConfig::new().session(&session);
    let decrypted = decrypt(&output, DecryptKey::Symmetric(&key), config).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), msg.as_bytes(), "VerifiedSession + {use_case:?} mismatch");
    let _ = std::fs::remove_file(&path);
}

/// Helper: establish a VerifiedSession, encrypt with (session + security_level),
/// write to file, read back, decrypt with session — process-isolated.
fn verified_session_security_level_roundtrip(level: SecurityLevel) {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session failed");
    let key = [0x51u8; 32];
    let msg = format!("VerifiedSession + SecurityLevel::{level:?}");

    let config = CryptoConfig::new()
        .session(&session)
        .security_level(level)
        .force_scheme(CryptoScheme::Symmetric);
    let encrypted =
        encrypt(msg.as_bytes(), EncryptKey::Symmetric(&key), config).expect("encrypt failed");
    let json = serialize_encrypted_output(&encrypted).expect("serialize failed");
    let path = std::env::temp_dir().join(format!("latticearc-vs-sl-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("write failed");

    let json_read = std::fs::read_to_string(&path).expect("read failed");
    let output = deserialize_encrypted_output(&json_read).expect("deserialize failed");
    let config = CryptoConfig::new().session(&session);
    let decrypted = decrypt(&output, DecryptKey::Symmetric(&key), config).expect("decrypt failed");
    assert_eq!(
        decrypted.as_slice(),
        msg.as_bytes(),
        "VerifiedSession + SecurityLevel::{level:?} mismatch"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn verified_session_file_storage_roundtrip() {
    verified_session_usecase_roundtrip(UseCase::FileStorage);
}

#[test]
fn verified_session_database_encryption_roundtrip() {
    verified_session_usecase_roundtrip(UseCase::DatabaseEncryption);
}

#[test]
fn verified_session_authentication_roundtrip() {
    verified_session_usecase_roundtrip(UseCase::Authentication);
}

#[test]
fn verified_session_iot_device_roundtrip() {
    verified_session_usecase_roundtrip(UseCase::IoTDevice);
}

#[test]
fn verified_session_api_security_roundtrip() {
    verified_session_usecase_roundtrip(UseCase::ApiSecurity);
}

#[test]
fn verified_session_security_level_standard_roundtrip() {
    verified_session_security_level_roundtrip(SecurityLevel::Standard);
}

#[test]
fn verified_session_security_level_high_roundtrip() {
    verified_session_security_level_roundtrip(SecurityLevel::High);
}

#[test]
fn verified_session_security_level_maximum_roundtrip() {
    verified_session_security_level_roundtrip(SecurityLevel::Maximum);
}

// ============================================================================
// SECTION 6: AAD (Additional Authenticated Data) + VerifiedSession
//
// Tests that AES-GCM-with-AAD works correctly under a Verified session,
// including wrong-AAD rejection and empty-AAD as valid bound context.
// ============================================================================

#[test]
fn aad_with_verified_session_roundtrip() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session failed");

    let key = [0x60u8; 32];
    let msg = b"AAD-bound payload under Verified session";
    let aad = b"request-id:42|tenant:acme";

    let ciphertext = encrypt_aes_gcm_with_aad(msg, &key, aad, SecurityMode::Verified(&session))
        .expect("encrypt with AAD failed");
    let decrypted =
        decrypt_aes_gcm_with_aad(&ciphertext, &key, aad, SecurityMode::Verified(&session))
            .expect("decrypt with AAD failed");
    assert_eq!(decrypted.as_slice(), msg);
}

#[test]
fn aad_with_verified_session_wrong_aad_rejected() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session failed");

    let key = [0x61u8; 32];
    let msg = b"AAD mismatch test";
    let correct_aad = b"correct-context";
    let wrong_aad = b"wrong-context";

    let ciphertext =
        encrypt_aes_gcm_with_aad(msg, &key, correct_aad, SecurityMode::Verified(&session))
            .expect("encrypt failed");
    let result =
        decrypt_aes_gcm_with_aad(&ciphertext, &key, wrong_aad, SecurityMode::Verified(&session));
    assert!(result.is_err(), "Wrong AAD must cause decryption failure");
}

#[test]
fn aad_with_verified_session_empty_aad_roundtrip() {
    let (pk, sk) = generate_keypair().expect("keygen failed");
    let session =
        VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session failed");

    let key = [0x62u8; 32];
    let msg = b"Empty AAD is a valid bound context";
    let empty_aad = b"";

    let ciphertext =
        encrypt_aes_gcm_with_aad(msg, &key, empty_aad, SecurityMode::Verified(&session))
            .expect("encrypt with empty AAD failed");
    let decrypted =
        decrypt_aes_gcm_with_aad(&ciphertext, &key, empty_aad, SecurityMode::Verified(&session))
            .expect("decrypt with empty AAD failed");
    assert_eq!(decrypted.as_slice(), msg);
}

// ============================================================================
// SECTION 7: ComplianceMode Process-Isolated Roundtrips
//
// Tests that each ComplianceMode variant works through the full
// encrypt → file → decrypt path with process isolation.
// ============================================================================

#[test]
fn compliance_mode_default_roundtrip() {
    let key = [0x70u8; 32];
    let msg = b"ComplianceMode::Default - no restrictions";
    process_isolated_roundtrip(msg, &key, CryptoConfig::new().compliance(ComplianceMode::Default));
}

// `ComplianceMode::Cnsa2_0` paths require the
// `fips` cargo feature; the default `cargo test --workspace` (no features)
// previously panicked with `FeatureNotAvailable`. Cfg-gate so the default
// test command works on a clean checkout.
#[cfg(feature = "fips")]
#[test]
fn compliance_mode_cnsa2_0_roundtrip() {
    // CNSA 2.0 (since 0.6.0) requires CryptoMode::PqOnly.
    let msg = b"ComplianceMode::Cnsa2_0 - PQ-only";
    let (pk, sk) =
        latticearc::generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem1024).expect("keygen");
    let config = CryptoConfig::new()
        .compliance(ComplianceMode::Cnsa2_0)
        .security_level(SecurityLevel::Maximum)
        .crypto_mode(latticearc::CryptoMode::PqOnly);
    let encrypted =
        encrypt(msg, EncryptKey::PqOnly(&pk), config).expect("CNSA 2.0 + PQ-only should succeed");

    let json = serialize_encrypted_output(&encrypted).expect("serialize");
    let path = std::env::temp_dir().join(format!("latticearc-cnsa-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("write");

    let json_read = std::fs::read_to_string(&path).expect("read");
    let deserialized = deserialize_encrypted_output(&json_read).expect("deserialize");
    let config = CryptoConfig::new()
        .compliance(ComplianceMode::Cnsa2_0)
        .security_level(SecurityLevel::Maximum)
        .crypto_mode(latticearc::CryptoMode::PqOnly);
    let decrypted = decrypt(&deserialized, DecryptKey::PqOnly(&sk), config).expect("decrypt");
    assert_eq!(decrypted.as_slice(), msg);
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "fips")]
#[test]
fn compliance_mode_cnsa2_0_rejects_standalone_aes() {
    // CNSA 2.0 rejects standalone classical schemes like AES-256-GCM.
    let key = [0x73u8; 32];
    let config = CryptoConfig::new()
        .compliance(ComplianceMode::Cnsa2_0)
        .security_level(SecurityLevel::Maximum)
        .crypto_mode(latticearc::CryptoMode::PqOnly)
        .force_scheme(CryptoScheme::Symmetric);
    let result = encrypt(b"should be rejected", EncryptKey::Symmetric(&key), config);
    assert!(result.is_err(), "CNSA 2.0 must reject standalone AES-256-GCM");
}

// ============================================================================
// SECTION 8: Scheme Verification Through File Serialization
//
// Tests that UseCase-driven scheme selection is preserved through
// hybrid encrypt → serialize → file → deserialize → assert scheme.
// No force_scheme() — the selector chooses the scheme.
// ============================================================================

/// Helper: expected scheme for a use case (mirrors scheme_contract_tests.rs)
fn expected_scheme_for_use_case(uc: UseCase) -> EncryptionScheme {
    match uc {
        UseCase::IoTDevice => EncryptionScheme::HybridMlKem512Aes256Gcm,

        UseCase::SecureMessaging
        | UseCase::VpnTunnel
        | UseCase::ApiSecurity
        | UseCase::DatabaseEncryption
        | UseCase::ConfigSecrets
        | UseCase::SessionToken
        | UseCase::AuditLog
        | UseCase::Authentication
        | UseCase::DigitalCertificate
        | UseCase::FinancialTransactions
        | UseCase::LegalDocuments
        | UseCase::BlockchainTransaction
        | UseCase::FirmwareSigning => EncryptionScheme::HybridMlKem768Aes256Gcm,

        UseCase::EmailEncryption
        | UseCase::FileStorage
        | UseCase::CloudStorage
        | UseCase::BackupArchive
        | UseCase::KeyExchange
        | UseCase::HealthcareRecords
        | UseCase::GovernmentClassified
        | UseCase::PaymentCard => EncryptionScheme::HybridMlKem1024Aes256Gcm,

        _ => unreachable!("unexpected UseCase variant"),
    }
}

/// Helper: encrypt with hybrid key (UseCase-driven, no force_scheme),
/// serialize to file, deserialize, assert scheme matches expected.
fn process_isolated_hybrid_scheme_check(use_case: UseCase, expected: EncryptionScheme) {
    let level =
        expected.ml_kem_level().unwrap_or_else(|| panic!("scheme {expected} has no ML-KEM level"));
    let (pk, _sk) = generate_hybrid_keypair_with_level(level)
        .unwrap_or_else(|e| panic!("keygen failed for {use_case:?}: {e}"));

    let data = b"Scheme verification through file serialization";
    let config = CryptoConfig::new().use_case(use_case);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
        .unwrap_or_else(|e| panic!("encrypt failed for {use_case:?}: {e}"));

    let json = serialize_encrypted_output(&encrypted)
        .unwrap_or_else(|e| panic!("serialize failed for {use_case:?}: {e}"));
    let path = std::env::temp_dir().join(format!("latticearc-scheme-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("write failed");

    // Reader: deserialize from file, assert scheme
    let json_read = std::fs::read_to_string(&path).expect("read failed");
    let deserialized = deserialize_encrypted_output(&json_read)
        .unwrap_or_else(|e| panic!("deserialize failed for {use_case:?}: {e}"));
    assert_eq!(
        deserialized.scheme(),
        &expected,
        "UseCase::{use_case:?} scheme mismatch after file roundtrip: got {}",
        deserialized.scheme()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn scheme_verified_iot_device_succeeds() {
    let expected = expected_scheme_for_use_case(UseCase::IoTDevice);
    process_isolated_hybrid_scheme_check(UseCase::IoTDevice, expected);
}

#[test]
fn scheme_verified_secure_messaging_succeeds() {
    let expected = expected_scheme_for_use_case(UseCase::SecureMessaging);
    process_isolated_hybrid_scheme_check(UseCase::SecureMessaging, expected);
}

#[test]
fn scheme_verified_file_storage_succeeds() {
    let expected = expected_scheme_for_use_case(UseCase::FileStorage);
    process_isolated_hybrid_scheme_check(UseCase::FileStorage, expected);
}

#[test]
fn scheme_verified_security_level_standard_succeeds() {
    // SecurityLevel::Standard → ML-KEM-512
    let expected = EncryptionScheme::HybridMlKem512Aes256Gcm;
    let level = MlKemSecurityLevel::MlKem512;
    let (pk, _sk) = generate_hybrid_keypair_with_level(level).expect("keygen");
    let data = b"SecurityLevel::Standard scheme through file";
    let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config).expect("encrypt");

    let json = serialize_encrypted_output(&encrypted).expect("serialize");
    let path = std::env::temp_dir().join(format!("latticearc-slscheme-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, json.as_bytes()).expect("write");

    let json_read = std::fs::read_to_string(&path).expect("read");
    let deserialized = deserialize_encrypted_output(&json_read).expect("deserialize");
    assert_eq!(
        deserialized.scheme(),
        &expected,
        "SecurityLevel::Standard scheme mismatch after file roundtrip"
    );
    let _ = std::fs::remove_file(&path);
}

// ============================================================================
// Design Doc Level 7 — Missing Scenario Tests
// ============================================================================

/// Scenario 4 (full): Key rotation under load.
/// Encrypt 100 messages with key v1 → rotate → encrypt 100 with v2 →
/// decrypt all 200 (100 with v1, 100 with v2) → destroy v1 → v1 decrypt fails.
/// Scenario 5: Multi-algorithm compatibility.
/// Encrypt the same plaintext with every EncryptionScheme variant →
/// serialize each → decrypt each → verify all match original.
#[test]
fn scenario_multi_algorithm_encrypt_same_plaintext_all_schemes_succeeds() {
    let plaintext = b"Same plaintext encrypted with every scheme variant";
    let sym_key = [0x55u8; 32];

    // Scheme 1: AES-256-GCM
    let enc_aes = encrypt(
        plaintext,
        EncryptKey::Symmetric(&sym_key),
        CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
    )
    .expect("AES-256-GCM encrypt");
    assert_eq!(enc_aes.scheme(), &EncryptionScheme::Aes256Gcm);

    // Scheme 2: ChaCha20-Poly1305 (non-FIPS only)
    #[cfg(not(feature = "fips"))]
    let enc_chacha = {
        let enc = encrypt(
            plaintext,
            EncryptKey::Symmetric(&sym_key),
            CryptoConfig::new().force_scheme(CryptoScheme::SymmetricChaCha20),
        )
        .expect("ChaCha20 encrypt");
        assert_eq!(enc.scheme(), &EncryptionScheme::ChaCha20Poly1305);
        Some(enc)
    };
    #[cfg(feature = "fips")]
    let _enc_chacha: Option<EncryptedOutput> = None;

    // Scheme 3-5: Hybrid ML-KEM-512/768/1024
    let levels = [
        (MlKemSecurityLevel::MlKem512, EncryptionScheme::HybridMlKem512Aes256Gcm),
        (MlKemSecurityLevel::MlKem768, EncryptionScheme::HybridMlKem768Aes256Gcm),
        (MlKemSecurityLevel::MlKem1024, EncryptionScheme::HybridMlKem1024Aes256Gcm),
    ];

    let mut hybrid_outputs: Vec<(
        EncryptedOutput,
        latticearc::hybrid::kem_hybrid::HybridKemSecretKey,
    )> = Vec::new();

    for (level, expected_scheme) in &levels {
        let (pk, sk) = generate_hybrid_keypair_with_level(*level).expect("keygen");
        // Force the scheme to match the key's security level
        let security = match level {
            MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
            MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
            MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
            _ => unreachable!("only 512/768/1024 levels are tested"),
        };
        let enc = encrypt(
            plaintext,
            EncryptKey::Hybrid(&pk),
            CryptoConfig::new().security_level(security),
        )
        .expect("hybrid encrypt");
        assert_eq!(enc.scheme(), expected_scheme);
        hybrid_outputs.push((enc, sk));
    }

    // Serialize all → drop → deserialize → decrypt → verify plaintext match
    let aes_json = serialize_encrypted_output(&enc_aes).expect("serialize aes");
    drop(enc_aes);
    let dec_aes: EncryptedOutput = deserialize_encrypted_output(&aes_json).expect("deser aes");
    let pt_aes =
        decrypt(&dec_aes, DecryptKey::Symmetric(&sym_key), CryptoConfig::new()).expect("dec aes");
    assert_eq!(pt_aes.as_slice(), plaintext, "AES-256-GCM roundtrip");

    #[cfg(not(feature = "fips"))]
    if let Some(enc_cc) = enc_chacha {
        let cc_json = serialize_encrypted_output(&enc_cc).expect("serialize chacha");
        drop(enc_cc);
        let dec_cc: EncryptedOutput = deserialize_encrypted_output(&cc_json).expect("deser chacha");
        let pt_cc = decrypt(&dec_cc, DecryptKey::Symmetric(&sym_key), CryptoConfig::new())
            .expect("dec chacha");
        assert_eq!(pt_cc.as_slice(), plaintext, "ChaCha20 roundtrip");
    }

    for (enc, sk) in &hybrid_outputs {
        let json = serialize_encrypted_output(enc).expect("serialize hybrid");
        let loaded: EncryptedOutput = deserialize_encrypted_output(&json).expect("deser hybrid");
        let pt = decrypt(&loaded, DecryptKey::Hybrid(sk), CryptoConfig::new()).expect("dec hybrid");
        assert_eq!(pt.as_slice(), plaintext, "Hybrid roundtrip for {:?}", enc.scheme());
    }

    // Verify schemes differ between outputs
    let schemes: Vec<&EncryptionScheme> = hybrid_outputs.iter().map(|(e, _)| e.scheme()).collect();
    assert_ne!(schemes[0], schemes[1], "512 and 768 schemes must differ");
    assert_ne!(schemes[1], schemes[2], "768 and 1024 schemes must differ");
}

/// Scenario 6: Compliance audit trail.
/// Establish zero-trust session → perform 10 crypto operations →
/// verify all produce results → verify no secret material in debug output.
#[test]
fn scenario_audit_trail_10_ops_no_secrets_in_debug_succeeds() {
    // Establish zero-trust session
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())
        .expect("session establishment");

    let key = [0x66u8; 32];

    // Perform 10 distinct crypto operations under verified session
    let mut debug_outputs: Vec<String> = Vec::new();
    let mut ciphertexts: Vec<EncryptedOutput> = Vec::new();

    for i in 0..10u32 {
        let msg = format!("Audit operation {i}: user=admin action=UPDATE resource=/api/data/{i}");
        let encrypted = encrypt(
            msg.as_bytes(),
            EncryptKey::Symmetric(&key),
            CryptoConfig::new()
                .use_case(UseCase::AuditLog)
                .session(&session)
                .force_scheme(CryptoScheme::Symmetric),
        )
        .unwrap_or_else(|e| panic!("Operation {i} encrypt failed: {e}"));

        // Capture debug output of encrypted data
        debug_outputs.push(format!("{encrypted:?}"));
        ciphertexts.push(encrypted);
    }

    // Verify all 10 operations produced ciphertext
    assert_eq!(ciphertexts.len(), 10, "Must have 10 encrypted outputs");
    for (i, ct) in ciphertexts.iter().enumerate() {
        assert!(!ct.ciphertext().is_empty(), "Op {i}: ciphertext must not be empty");
    }

    // Verify NO secret material appears in debug output
    let key_hex = hex::encode(key);
    let key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    for (i, dbg) in debug_outputs.iter().enumerate() {
        assert!(!dbg.contains(&key_hex), "Op {i}: debug output must not contain key hex");
        assert!(!dbg.contains(&key_b64), "Op {i}: debug output must not contain key base64");
        // Check raw key bytes don't appear
        // Check that repeated key byte patterns don't appear in debug output
        for byte in &key {
            if *byte != 0 && *byte != 1 {
                assert!(
                    !dbg.contains(&format!("[{byte}, {byte}, {byte}, {byte}]")),
                    "Op {i}: debug output must not contain repeated key byte patterns"
                );
            }
        }
    }

    // Decrypt all 10 to verify integrity
    for (i, ct) in ciphertexts.iter().enumerate() {
        let decrypted =
            decrypt(ct, DecryptKey::Symmetric(&key), CryptoConfig::new()).expect("decrypt");
        let expected =
            format!("Audit operation {i}: user=admin action=UPDATE resource=/api/data/{i}");
        assert_eq!(
            std::str::from_utf8(&decrypted).unwrap(),
            expected,
            "Op {i}: decrypted content mismatch"
        );
    }

    // Verify timestamps are monotonically non-decreasing
    let timestamps: Vec<u64> = ciphertexts.iter().map(EncryptedOutput::timestamp).collect();
    for window in timestamps.windows(2) {
        assert!(
            window[0] <= window[1],
            "Timestamps must be monotonic: {} > {}",
            window[0],
            window[1]
        );
    }
}
