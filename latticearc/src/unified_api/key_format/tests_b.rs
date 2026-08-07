//! Unit and integration tests for `key_format` (continued from `tests_a`):
//! file I/O roundtrips, legacy-format parsing, every-algorithm JSON/CBOR
//! roundtrips, edge cases, `UseCase`/`SecurityLevel` constructors, full
//! provisioning/encrypt/decrypt process simulations, error paths, and
//! `ConstantTimeEq` regression tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::useless_vec,
    clippy::panic,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]

use super::portable_key_core::{resolve_security_level_algorithm, resolve_use_case_algorithm};
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use chrono::{DateTime, Utc};
use subtle::ConstantTimeEq;

// --- File I/O ---

#[test]
fn test_json_file_roundtrip_via_disk_roundtrip() {
    let dir = std::env::temp_dir().join("latticearc_key_format_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_key.json");

    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Public,
        KeyData::from_raw(&vec![0xAA; 1184]),
    );
    key.write_to_file(&path).unwrap();
    let restored = PortableKey::read_from_file(&path).unwrap();

    assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);
    assert_eq!(restored.key_data().decode_raw().unwrap().len(), 1184);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_cbor_file_roundtrip_via_disk_roundtrip() {
    let dir = std::env::temp_dir().join("latticearc_key_cbor_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_key.cbor");

    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Public,
        KeyData::from_raw(&vec![0xAA; 1184]),
    );
    key.write_cbor_to_file(&path).unwrap();
    let restored = PortableKey::read_cbor_from_file(&path).unwrap();

    assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(unix)]
#[test]
fn test_file_permissions_secret_key_are_restricted_succeeds() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join("latticearc_key_perms_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("secret_key.json");

    let key =
        PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&[0u8; 32]));
    key.write_to_file(&path).unwrap();

    let perms = std::fs::metadata(&path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o600);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

// --- Legacy format ---

#[test]
fn test_from_legacy_json_succeeds() {
    let legacy = r#"{
        "algorithm": "ML-DSA-65",
        "key_type": "public",
        "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "label": "Test key"
    }"#;

    let key = PortableKey::from_legacy_json(legacy).unwrap();
    assert_eq!(key.algorithm(), KeyAlgorithm::MlDsa65);
    assert_eq!(key.key_type(), KeyType::Public);
    assert_eq!(key.label(), Some("Test key"));
}

#[test]
fn test_from_legacy_json_secret_succeeds() {
    let legacy = r#"{
        "algorithm": "ed25519",
        "key_type": "private",
        "key": "AQIDBA=="
    }"#;
    let key = PortableKey::from_legacy_json(legacy).unwrap();
    assert_eq!(key.key_type(), KeyType::Secret);
}

#[test]
fn test_from_legacy_json_unknown_algorithm_fails() {
    let legacy = r#"{"algorithm":"UNKNOWN-999","key_type":"public","key":"AQID"}"#;
    assert!(PortableKey::from_legacy_json(legacy).is_err());
}

#[test]
fn test_from_legacy_json_unknown_key_type_fails() {
    let legacy = r#"{"algorithm":"ed25519","key_type":"unknown","key":"AQID"}"#;
    assert!(PortableKey::from_legacy_json(legacy).is_err());
}

#[test]
fn test_from_legacy_json_hybrid_algorithm_fails() {
    // The legacy schema has a single `key` field and cannot represent a
    // hybrid key's composite components; import must reject it with the
    // format-limitation reason, not the misleading "must use composite
    // key data" message that surfaces if the key reaches `validate()`.
    let legacy = r#"{
        "algorithm": "hybrid-ml-kem-768-x25519",
        "key_type": "public",
        "key": "AQID"
    }"#;
    let err = PortableKey::from_legacy_json(legacy)
        .expect_err("hybrid algorithm must be rejected by the legacy importer");
    assert!(err.to_string().contains("Legacy key format cannot represent hybrid"), "got: {err}");
}

// --- Every algorithm roundtrip (JSON + CBOR) ---

#[test]
fn test_every_single_algorithm_roundtrip() {
    let single_algorithms = [
        (KeyAlgorithm::MlKem512, KeyType::Public),
        (KeyAlgorithm::MlKem768, KeyType::Public),
        (KeyAlgorithm::MlKem1024, KeyType::Secret),
        (KeyAlgorithm::MlDsa44, KeyType::Public),
        (KeyAlgorithm::MlDsa65, KeyType::Secret),
        (KeyAlgorithm::MlDsa87, KeyType::Public),
        (KeyAlgorithm::SlhDsaShake128s, KeyType::Public),
        (KeyAlgorithm::SlhDsaShake192s, KeyType::Public),
        (KeyAlgorithm::SlhDsaShake256s, KeyType::Secret),
        (KeyAlgorithm::FnDsa512, KeyType::Public),
        (KeyAlgorithm::FnDsa1024, KeyType::Secret),
        (KeyAlgorithm::Ed25519, KeyType::Public),
        (KeyAlgorithm::X25519, KeyType::Secret),
        (KeyAlgorithm::Aes256, KeyType::Symmetric),
        (KeyAlgorithm::ChaCha20, KeyType::Symmetric),
    ];

    for (alg, kt) in &single_algorithms {
        let key = PortableKey::new(*alg, *kt, KeyData::from_raw(&[0x42; 32]));

        // JSON roundtrip
        let json = key.to_json().unwrap();
        let from_json = PortableKey::from_json(&json).unwrap();
        assert_eq!(from_json.algorithm(), *alg);

        // CBOR roundtrip
        let cbor = key.to_cbor().unwrap();
        let from_cbor = PortableKey::from_cbor(&cbor).unwrap();
        assert_eq!(from_cbor.algorithm(), *alg);
        assert_eq!(from_cbor.key_type(), *kt);
    }
}

#[test]
fn test_every_hybrid_algorithm_roundtrip() {
    let hybrid_algorithms = [
        (KeyAlgorithm::HybridMlKem512X25519, KeyType::Public),
        (KeyAlgorithm::HybridMlKem768X25519, KeyType::Secret),
        (KeyAlgorithm::HybridMlKem1024X25519, KeyType::Public),
        (KeyAlgorithm::HybridMlDsa44Ed25519, KeyType::Public),
        (KeyAlgorithm::HybridMlDsa65Ed25519, KeyType::Secret),
        (KeyAlgorithm::HybridMlDsa87Ed25519, KeyType::Public),
    ];

    for (alg, kt) in &hybrid_algorithms {
        let key = PortableKey::new(*alg, *kt, KeyData::from_composite(&[0xAA; 64], &[0xBB; 32]));

        // JSON roundtrip
        let json = key.to_json().unwrap();
        let from_json = PortableKey::from_json(&json).unwrap();
        assert_eq!(from_json.algorithm(), *alg);

        // CBOR roundtrip
        let cbor = key.to_cbor().unwrap();
        let from_cbor = PortableKey::from_cbor(&cbor).unwrap();
        assert_eq!(from_cbor.algorithm(), *alg);
        assert_eq!(from_cbor.key_type(), *kt);
    }
}

// --- Edge cases ---

#[test]
fn test_from_json_invalid_json_fails() {
    assert!(PortableKey::from_json("not json").is_err());
}

#[test]
fn test_from_cbor_invalid_data_fails() {
    assert!(PortableKey::from_cbor(&[0xFF, 0xFF]).is_err());
}

#[test]
fn test_from_json_missing_fields_fails() {
    assert!(PortableKey::from_json(r#"{"version":1}"#).is_err());
}

#[test]
fn test_read_nonexistent_file_fails() {
    assert!(PortableKey::read_from_file(std::path::Path::new("/nonexistent/path.json")).is_err());
}

#[test]
fn test_version_is_current_format_has_correct_size() {
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    assert_eq!(key.version(), PortableKey::CURRENT_VERSION);
}

#[test]
fn test_with_created_sets_timestamp_succeeds() {
    let ts = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
    let key = PortableKey::with_created(
        KeyAlgorithm::Ed25519,
        KeyType::Public,
        KeyData::from_raw(&[0u8; 32]),
        ts,
    );
    assert_eq!(*key.created(), ts);
}

#[test]
fn test_pretty_json_contains_newlines_and_indentation_is_correct() {
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let pretty = key.to_json_pretty().unwrap();
    assert!(pretty.contains('\n'));
}

// --- UseCase / SecurityLevel constructors ---

#[test]
fn test_for_use_case_file_storage_is_correct() {
    use crate::types::types::UseCase;
    let key = PortableKey::for_use_case(
        UseCase::FileStorage,
        KeyType::Public,
        KeyData::from_raw(&vec![0xAA; 1568]),
    );
    assert_eq!(key.use_case(), Some(UseCase::FileStorage));
    assert!(key.security_level().is_none());
    // FileStorage → Level 5 → HybridMlKem1024X25519
    assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem1024X25519);
}

#[test]
fn test_for_use_case_iot_is_correct() {
    use crate::types::types::UseCase;
    let key = PortableKey::for_use_case(
        UseCase::IoTDevice,
        KeyType::Public,
        KeyData::from_raw(&vec![0xBB; 800]),
    );
    assert_eq!(key.use_case(), Some(UseCase::IoTDevice));
    // IoTDevice → Level 1 → HybridMlKem512X25519
    assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem512X25519);
}

#[test]
fn test_for_use_case_secure_messaging_is_correct() {
    use crate::types::types::UseCase;
    let key = PortableKey::for_use_case(
        UseCase::SecureMessaging,
        KeyType::Public,
        KeyData::from_raw(&vec![0xCC; 1184]),
    );
    // SecureMessaging → Level 3 → HybridMlKem768X25519
    assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
}

#[test]
fn test_for_security_level_high_is_correct() {
    use crate::types::types::SecurityLevel;
    let key = PortableKey::for_security_level(
        SecurityLevel::High,
        KeyType::Public,
        KeyData::from_raw(&vec![0xDD; 1184]),
    );
    assert!(key.use_case().is_none());
    assert_eq!(key.security_level(), Some(SecurityLevel::High));
    assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
}

#[test]
fn test_for_use_case_with_level_security_takes_precedence_succeeds() {
    use crate::types::types::{SecurityLevel, UseCase};
    // UseCase::IoTDevice would resolve to MlKem512
    // SecurityLevel::Maximum should take precedence → MlKem1024
    let key = PortableKey::for_use_case_with_level(
        UseCase::IoTDevice,
        SecurityLevel::Maximum,
        KeyType::Public,
        KeyData::from_raw(&vec![0xFF; 1568]),
    );
    assert_eq!(key.use_case(), Some(UseCase::IoTDevice));
    assert_eq!(key.security_level(), Some(SecurityLevel::Maximum));
    // SecurityLevel takes precedence
    assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem1024X25519);
}

#[test]
fn test_for_use_case_json_includes_use_case_field_succeeds() {
    use crate::types::types::UseCase;
    let key = PortableKey::for_use_case(
        UseCase::DatabaseEncryption,
        KeyType::Public,
        KeyData::from_raw(&[0u8; 32]),
    );
    let json = key.to_json().unwrap();
    assert!(json.contains("use_case"));
    assert!(json.contains("database-encryption"));
}

#[test]
fn test_for_security_level_json_includes_security_level_field_succeeds() {
    use crate::types::types::SecurityLevel;
    let key = PortableKey::for_security_level(
        SecurityLevel::Standard,
        KeyType::Public,
        KeyData::from_raw(&[0u8; 32]),
    );
    let json = key.to_json().unwrap();
    assert!(json.contains("security_level"));
    assert!(json.contains("standard"));
}

#[test]
fn test_for_use_case_cbor_roundtrip() {
    use crate::types::types::UseCase;
    let key = PortableKey::for_use_case(
        UseCase::HealthcareRecords,
        KeyType::Secret,
        KeyData::from_composite(&[0xAA; 64], &[0xBB; 32]),
    );
    let cbor = key.to_cbor().unwrap();
    let restored = PortableKey::from_cbor(&cbor).unwrap();
    assert_eq!(restored.use_case(), Some(UseCase::HealthcareRecords));
    assert_eq!(restored.algorithm(), KeyAlgorithm::HybridMlKem1024X25519);
}

// ====================================================================
// E2E Proof Tests — real-world scenarios through PortableKey format
// Run with: cargo test -p latticearc --release --all-features -- key_format::tests::proof -- --nocapture
// ====================================================================

/// PROOF: File storage — two-process simulation.
/// Process A: generates keypair, exports to JSON files.
/// Process B: loads JSON files, encrypts (encapsulate) with PK.
/// Process A: loads SK from JSON, decrypts (decapsulate). Shared secrets match.
/// Neither process touches the other's in-memory key objects.
#[test]
fn proof_e2e_file_storage_two_process() {
    use crate::hybrid::kem_hybrid;
    use crate::types::types::UseCase;

    // === PROCESS A: Key provisioning ===
    let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
    let (portable_pk, portable_sk) =
        PortableKey::from_hybrid_kem_keypair(UseCase::FileStorage, &pk, &sk).unwrap();
    let pk_json = portable_pk.to_json().unwrap();
    let pk_json_len = pk_json.len();
    let sk_json = portable_sk.to_json().unwrap();
    let sk_json_len = sk_json.len();
    // Process A drops original keys — only JSON survives
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // === PROCESS B: Sender encrypts using PK from JSON ===
    let sender_pk = PortableKey::from_json(&pk_json).unwrap();
    let sender_hybrid_pk = sender_pk.to_hybrid_public_key().unwrap();
    let encapsulated = kem_hybrid::encapsulate(&sender_hybrid_pk).unwrap();
    let sender_shared_secret = encapsulated.expose_secret().to_vec();

    // === PROCESS A: Receiver decrypts using SK from JSON ===
    let receiver_sk_portable = PortableKey::from_json(&sk_json).unwrap();
    let receiver_sk = receiver_sk_portable.to_hybrid_secret_key().unwrap();
    let receiver_shared_secret = kem_hybrid::decapsulate(&receiver_sk, &encapsulated).unwrap();
    let secrets_match: bool =
        receiver_shared_secret.expose_secret().ct_eq(sender_shared_secret.as_slice()).into();
    let uc_preserved = receiver_sk_portable.use_case() == Some(UseCase::FileStorage);

    assert!(secrets_match, "Shared secrets must match across processes");
    assert!(uc_preserved);

    println!(
        "[PROOF] {{\"test\":\"e2e_file_storage_two_process\",\
         \"category\":\"key-format\",\
         \"use_case\":\"file-storage\",\
         \"algorithm\":\"hybrid-ml-kem-768-x25519\",\
         \"format\":\"json\",\
         \"pk_json_bytes\":{pk_json_len},\
         \"sk_json_bytes\":{sk_json_len},\
         \"shared_secret_bytes\":{},\
         \"cross_process_kem_match\":{secrets_match},\
         \"use_case_preserved\":{uc_preserved},\
         \"status\":\"PASS\"}}",
        receiver_shared_secret.len(),
    );
}

/// PROOF: Secure messaging over CBOR wire — two-process simulation.
/// Process A: generates keypair, sends PK as CBOR over wire.
/// Process B: receives CBOR PK, encapsulates.
/// Process A: receives ciphertext, decapsulates with SK reconstructed from CBOR.
#[test]
fn proof_e2e_secure_messaging_cbor_two_process() {
    use crate::hybrid::kem_hybrid;
    use crate::types::types::UseCase;

    // === PROCESS A: Key provisioning, export to CBOR ===
    let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
    let (portable_pk, portable_sk) =
        PortableKey::from_hybrid_kem_keypair(UseCase::SecureMessaging, &pk, &sk).unwrap();
    let pk_cbor = portable_pk.to_cbor().unwrap();
    let pk_cbor_len = pk_cbor.len();
    let sk_cbor = portable_sk.to_cbor().unwrap();
    let sk_cbor_len = sk_cbor.len();
    let pk_json_len = portable_pk.to_json().unwrap().len();
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // === PROCESS B: Receives PK CBOR, encapsulates ===
    let sender_pk = PortableKey::from_cbor(&pk_cbor).unwrap();
    let sender_hybrid_pk = sender_pk.to_hybrid_public_key().unwrap();
    let encapsulated = kem_hybrid::encapsulate(&sender_hybrid_pk).unwrap();
    let sender_ss = encapsulated.expose_secret().to_vec();

    // === PROCESS A: Reconstructs SK from CBOR, decapsulates ===
    let receiver_sk_portable = PortableKey::from_cbor(&sk_cbor).unwrap();
    let receiver_sk = receiver_sk_portable.to_hybrid_secret_key().unwrap();
    let receiver_ss = kem_hybrid::decapsulate(&receiver_sk, &encapsulated).unwrap();
    let secrets_match: bool = receiver_ss.expose_secret().ct_eq(sender_ss.as_slice()).into();

    assert!(secrets_match);
    assert!(pk_cbor_len < pk_json_len);

    println!(
        "[PROOF] {{\"test\":\"e2e_secure_messaging_cbor_two_process\",\
         \"category\":\"key-format\",\
         \"use_case\":\"secure-messaging\",\
         \"format\":\"cbor\",\
         \"pk_cbor_bytes\":{pk_cbor_len},\
         \"sk_cbor_bytes\":{sk_cbor_len},\
         \"pk_json_bytes\":{pk_json_len},\
         \"cbor_savings_pct\":{:.1},\
         \"cross_process_kem_match\":{secrets_match},\
         \"status\":\"PASS\"}}",
        (1.0 - (pk_cbor_len as f64 / pk_json_len as f64)) * 100.0,
    );
}

/// PROOF: Legal document signing — two-process simulation.
/// Process A (signer): generates sig keypair, exports SK to JSON, signs document.
/// Process B (verifier): receives PK JSON + signed document, verifies signature.
/// Verifier has no access to signer's in-memory key objects.
#[test]
fn proof_e2e_legal_document_signing_two_process() {
    use crate::hybrid::sig_hybrid;
    use crate::types::types::UseCase;

    // === SIGNER (Process A): Generate, export, sign ===
    let (pk, sk) = sig_hybrid::generate_keypair().unwrap();
    let (portable_pk, _portable_sk) =
        PortableKey::from_hybrid_sig_keypair(UseCase::LegalDocuments, &pk, &sk).unwrap();
    let pk_json = portable_pk.to_json().unwrap();

    let message = b"WHEREAS the parties agree to the following terms and conditions...";
    let signature = sig_hybrid::sign(&sk, message).unwrap();
    let sig_bytes = signature.ml_dsa_sig().len() + signature.ed25519_sig().len();

    // Signer drops keys — only JSON + signature remain
    drop(pk);
    drop(sk);
    drop(portable_pk);

    // === VERIFIER (Process B): Load PK from JSON, verify ===
    let verifier_pk = PortableKey::from_json(&pk_json).unwrap();
    let verifier_hybrid_pk = verifier_pk.to_hybrid_sig_public_key().unwrap();
    let valid = sig_hybrid::verify(&verifier_hybrid_pk, message, &signature).unwrap();
    let uc_ok = verifier_pk.use_case() == Some(UseCase::LegalDocuments);
    let alg_ok = verifier_pk.algorithm() == KeyAlgorithm::HybridMlDsa65Ed25519;

    assert!(valid, "Signature must verify with JSON-restored PK");
    assert!(uc_ok);
    assert!(alg_ok);

    println!(
        "[PROOF] {{\"test\":\"e2e_legal_document_signing_two_process\",\
         \"category\":\"key-format\",\
         \"use_case\":\"legal-documents\",\
         \"algorithm\":\"hybrid-ml-dsa-65-ed25519\",\
         \"message_len\":{},\
         \"total_sig_bytes\":{sig_bytes},\
         \"cross_process_verify\":{valid},\
         \"use_case_preserved\":{uc_ok},\
         \"status\":\"PASS\"}}",
        message.len(),
    );
}

/// PROOF: Key file persistence — two-process simulation with disk files.
/// Process A: generates keypair, writes PK + SK to files.
/// Process B: reads PK file, encapsulates.
/// Process A: reads SK file, decapsulates. Shared secrets match.
#[test]
fn proof_e2e_key_file_persistence_two_process() {
    use crate::hybrid::kem_hybrid;
    use crate::types::types::UseCase;

    let dir = std::env::temp_dir().join("latticearc_proof_key_file_e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let pk_json_path = dir.join("cloud.pub.json");
    let sk_json_path = dir.join("cloud.sec.json");
    let pk_cbor_path = dir.join("cloud.pub.cbor");

    // === PROCESS A: Key provisioning, write to files ===
    let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
    let (portable_pk, portable_sk) =
        PortableKey::from_hybrid_kem_keypair(UseCase::CloudStorage, &pk, &sk).unwrap();
    portable_pk.write_to_file(&pk_json_path).unwrap();
    portable_pk.write_cbor_to_file(&pk_cbor_path).unwrap();
    portable_sk.write_to_file(&sk_json_path).unwrap();
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // === PROCESS B: Load PK from JSON file, encapsulate ===
    let sender_pk =
        PortableKey::read_from_file(&pk_json_path).unwrap().to_hybrid_public_key().unwrap();
    let encapsulated = kem_hybrid::encapsulate(&sender_pk).unwrap();
    let sender_ss = encapsulated.expose_secret().to_vec();

    // === PROCESS A: Load SK from JSON file, decapsulate ===
    let receiver_sk_portable = PortableKey::read_from_file(&sk_json_path).unwrap();
    let receiver_sk = receiver_sk_portable.to_hybrid_secret_key().unwrap();
    let receiver_ss = kem_hybrid::decapsulate(&receiver_sk, &encapsulated).unwrap();
    let json_match = receiver_ss.expose_secret() == sender_ss.as_slice();

    // Also verify CBOR PK file works
    let cbor_pk =
        PortableKey::read_cbor_from_file(&pk_cbor_path).unwrap().to_hybrid_public_key().unwrap();
    let enc2 = kem_hybrid::encapsulate(&cbor_pk).unwrap();
    let dec2 = kem_hybrid::decapsulate(&receiver_sk, &enc2).unwrap();
    let cbor_match = dec2.expose_secret() == enc2.expose_secret();

    let json_size = std::fs::metadata(&pk_json_path).unwrap().len();
    let cbor_size = std::fs::metadata(&pk_cbor_path).unwrap().len();

    assert!(json_match);
    assert!(cbor_match);

    println!(
        "[PROOF] {{\"test\":\"e2e_key_file_persistence_two_process\",\
         \"category\":\"key-format\",\
         \"use_case\":\"cloud-storage\",\
         \"json_file_bytes\":{json_size},\
         \"cbor_file_bytes\":{cbor_size},\
         \"json_cross_process_kem\":{json_match},\
         \"cbor_cross_process_kem\":{cbor_match},\
         \"status\":\"PASS\"}}",
    );

    let _ = std::fs::remove_file(&pk_json_path);
    let _ = std::fs::remove_file(&sk_json_path);
    let _ = std::fs::remove_file(&pk_cbor_path);
    let _ = std::fs::remove_dir(&dir);
}

/// PROOF: Cross-format consistency — same key serialized to JSON and CBOR,
/// both produce identical crypto results in separate decapsulations.
#[test]
fn proof_e2e_cross_format_consistency() {
    use crate::hybrid::kem_hybrid;
    use crate::types::types::UseCase;

    let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
    let (portable_pk, portable_sk) =
        PortableKey::from_hybrid_kem_keypair(UseCase::DatabaseEncryption, &pk, &sk).unwrap();
    let json = portable_pk.to_json().unwrap();
    let cbor = portable_pk.to_cbor().unwrap();
    let sk_json = portable_sk.to_json().unwrap();
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // Restore from both formats
    let pk_from_json = PortableKey::from_json(&json).unwrap().to_hybrid_public_key().unwrap();
    let pk_from_cbor = PortableKey::from_cbor(&cbor).unwrap().to_hybrid_public_key().unwrap();
    let sk_restored = PortableKey::from_json(&sk_json).unwrap().to_hybrid_secret_key().unwrap();

    let keys_match = pk_from_json.ml_kem_pk() == pk_from_cbor.ml_kem_pk()
        && pk_from_json.ecdh_pk() == pk_from_cbor.ecdh_pk();

    // Encapsulate with JSON-restored PK, decapsulate with JSON-restored SK
    let enc1 = kem_hybrid::encapsulate(&pk_from_json).unwrap();
    let dec1 = kem_hybrid::decapsulate(&sk_restored, &enc1).unwrap();
    let json_kem_ok = dec1.expose_secret() == enc1.expose_secret();

    // Encapsulate with CBOR-restored PK, decapsulate with same SK
    let enc2 = kem_hybrid::encapsulate(&pk_from_cbor).unwrap();
    let dec2 = kem_hybrid::decapsulate(&sk_restored, &enc2).unwrap();
    let cbor_kem_ok = dec2.expose_secret() == enc2.expose_secret();

    assert!(keys_match);
    assert!(json_kem_ok);
    assert!(cbor_kem_ok);

    println!(
        "[PROOF] {{\"test\":\"e2e_cross_format_consistency\",\
         \"category\":\"key-format\",\
         \"json_bytes\":{},\
         \"cbor_bytes\":{},\
         \"key_material_match\":{keys_match},\
         \"json_kem_cross_process\":{json_kem_ok},\
         \"cbor_kem_cross_process\":{cbor_kem_ok},\
         \"status\":\"PASS\"}}",
        json.len(),
        cbor.len(),
    );
}

/// PROOF: Enterprise metadata survives roundtrip and doesn't break crypto.
/// Metadata added by enterprise crate persists through JSON + CBOR.
/// Crypto operations work identically with or without metadata.
#[test]
fn proof_e2e_enterprise_metadata_roundtrip() {
    use crate::hybrid::kem_hybrid;
    use crate::types::types::UseCase;

    let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
    let (mut portable_pk, portable_sk) =
        PortableKey::from_hybrid_kem_keypair(UseCase::HealthcareRecords, &pk, &sk).unwrap();

    // Enterprise crate adds metadata
    portable_pk.set_label("HIPAA-compliant DEK").unwrap();
    portable_pk
        .set_metadata(
            "compliance".to_string(),
            serde_json::json!({"standard": "HIPAA", "audit_id": "AUD-2026-0042"}),
        )
        .unwrap();
    portable_pk.set_metadata("department".to_string(), serde_json::json!("cardiology")).unwrap();

    let pk_json = portable_pk.to_json().unwrap();
    let sk_json = portable_sk.to_json().unwrap();
    let pk_cbor = portable_pk.to_cbor().unwrap();
    drop(pk);
    drop(sk);
    drop(portable_pk);
    drop(portable_sk);

    // JSON: metadata preserved + crypto works
    let from_json = PortableKey::from_json(&pk_json).unwrap();
    let label_ok = from_json.label() == Some("HIPAA-compliant DEK");
    let compliance_ok = from_json
        .metadata()
        .get("compliance")
        .and_then(|v| v.get("standard"))
        .and_then(|v| v.as_str())
        == Some("HIPAA");
    let dept_ok = from_json.metadata().get("department") == Some(&serde_json::json!("cardiology"));
    let json_pk = from_json.to_hybrid_public_key().unwrap();
    let json_sk = PortableKey::from_json(&sk_json).unwrap().to_hybrid_secret_key().unwrap();
    let enc = kem_hybrid::encapsulate(&json_pk).unwrap();
    let dec = kem_hybrid::decapsulate(&json_sk, &enc).unwrap();
    let kem_ok = dec.expose_secret() == enc.expose_secret();

    // CBOR: metadata preserved
    let from_cbor = PortableKey::from_cbor(&pk_cbor).unwrap();
    let cbor_label_ok = from_cbor.label() == Some("HIPAA-compliant DEK");
    let cbor_audit_ok = from_cbor
        .metadata()
        .get("compliance")
        .and_then(|v| v.get("audit_id"))
        .and_then(|v| v.as_str())
        == Some("AUD-2026-0042");

    assert!(label_ok);
    assert!(compliance_ok);
    assert!(dept_ok);
    assert!(cbor_label_ok);
    assert!(cbor_audit_ok);
    assert!(kem_ok);

    let metadata_count = from_json.metadata().len();

    println!(
        "[PROOF] {{\"test\":\"e2e_enterprise_metadata_roundtrip\",\
         \"category\":\"key-format\",\
         \"use_case\":\"healthcare-records\",\
         \"metadata_fields\":{metadata_count},\
         \"json_label\":{label_ok},\
         \"json_compliance\":{compliance_ok},\
         \"cbor_label\":{cbor_label_ok},\
         \"cbor_audit\":{cbor_audit_ok},\
         \"cross_process_kem_with_metadata\":{kem_ok},\
         \"status\":\"PASS\"}}",
    );
}

/// PROOF: SecurityLevel precedence — when both use_case and security_level
/// are set, security_level determines the algorithm.
#[test]
fn proof_e2e_security_level_precedence() {
    use crate::types::types::{SecurityLevel, UseCase};

    // IoTDevice → HybridMlKem512X25519 (Level 1)
    // Maximum → HybridMlKem1024X25519 (Level 5)
    // Security level should win
    let key = PortableKey::for_use_case_with_level(
        UseCase::IoTDevice,
        SecurityLevel::Maximum,
        KeyType::Public,
        KeyData::from_composite(&[0x42; 1568], &[0x43; 32]),
    );

    let uc_algo = resolve_use_case_algorithm(UseCase::IoTDevice);
    let sl_algo = resolve_security_level_algorithm(SecurityLevel::Maximum);
    let actual_algo = key.algorithm();
    let precedence_correct = actual_algo == sl_algo && actual_algo != uc_algo;

    // JSON roundtrip preserves both fields
    let json = key.to_json().unwrap();
    let restored = PortableKey::from_json(&json).unwrap();
    let uc_preserved = restored.use_case() == Some(UseCase::IoTDevice);
    let sl_preserved = restored.security_level() == Some(SecurityLevel::Maximum);
    let algo_preserved = restored.algorithm() == KeyAlgorithm::HybridMlKem1024X25519;

    assert!(precedence_correct);
    assert!(uc_preserved);
    assert!(sl_preserved);
    assert!(algo_preserved);

    println!(
        "[PROOF] {{\"test\":\"e2e_security_level_precedence\",\
         \"category\":\"key-format\",\
         \"use_case\":\"io-t-device\",\
         \"security_level\":\"maximum\",\
         \"use_case_would_select\":\"{uc_algo:?}\",\
         \"security_level_selects\":\"{sl_algo:?}\",\
         \"actual_algorithm\":\"{actual_algo:?}\",\
         \"precedence_correct\":{precedence_correct},\
         \"use_case_preserved\":{uc_preserved},\
         \"security_level_preserved\":{sl_preserved},\
         \"algorithm_preserved\":{algo_preserved},\
         \"status\":\"PASS\"}}",
    );
}

// --- Error path tests ---

#[test]
fn test_to_hybrid_public_key_wrong_algorithm_fails() {
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    assert!(key.to_hybrid_public_key().is_err());
}

#[test]
fn test_to_hybrid_sig_public_key_wrong_algorithm_fails() {
    let key =
        PortableKey::new(KeyAlgorithm::MlKem768, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    assert!(key.to_hybrid_sig_public_key().is_err());
}

#[test]
fn test_all_use_cases_resolve_to_algorithm_is_correct() {
    use crate::types::types::UseCase;
    let all = [
        UseCase::SecureMessaging,
        UseCase::EmailEncryption,
        UseCase::VpnTunnel,
        UseCase::ApiSecurity,
        UseCase::FileStorage,
        UseCase::DatabaseEncryption,
        UseCase::CloudStorage,
        UseCase::BackupArchive,
        UseCase::ConfigSecrets,
        UseCase::Authentication,
        UseCase::SessionToken,
        UseCase::DigitalCertificate,
        UseCase::KeyExchange,
        UseCase::FinancialTransactions,
        UseCase::LegalDocuments,
        UseCase::BlockchainTransaction,
        UseCase::HealthcareRecords,
        UseCase::GovernmentClassified,
        UseCase::PaymentCard,
        UseCase::IoTDevice,
        UseCase::FirmwareSigning,
        UseCase::AuditLog,
    ];
    for uc in &all {
        let key = PortableKey::for_use_case(*uc, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        // Every use case must resolve to a valid algorithm
        assert!(
            key.algorithm().is_hybrid() || matches!(key.algorithm(), KeyAlgorithm::MlKem1024),
            "UseCase {:?} resolved to unexpected algorithm {:?}",
            uc,
            key.algorithm()
        );
    }
}

#[test]
fn test_all_security_levels_resolve_to_algorithm_is_correct() {
    use crate::types::types::SecurityLevel;
    let levels = [
        (SecurityLevel::Standard, KeyAlgorithm::HybridMlKem512X25519),
        (SecurityLevel::High, KeyAlgorithm::HybridMlKem768X25519),
        (SecurityLevel::Maximum, KeyAlgorithm::HybridMlKem1024X25519),
    ];
    for (level, expected) in &levels {
        let key =
            PortableKey::for_security_level(*level, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        assert_eq!(key.algorithm(), *expected, "Level {:?}", level);
    }
}

// --- ConstantTimeEq regression tests (#49) ---

fn ct_fixture_ts() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap().with_timezone(&Utc)
}

fn ct_fixture_key(
    algorithm: KeyAlgorithm,
    key_type: KeyType,
    raw: u8,
    ts: DateTime<Utc>,
) -> PortableKey {
    PortableKey::with_created(algorithm, key_type, KeyData::from_raw(&[raw; 32]), ts)
}

fn ct_fixture_encrypted(ciphertext_byte: u8) -> KeyData {
    KeyData::Encrypted {
        enc: ENCRYPTED_ENVELOPE_VERSION,
        kdf: PBKDF2_KDF_ID.to_string(),
        kdf_iterations: PBKDF2_DEFAULT_ITERATIONS,
        kdf_salt: BASE64_ENGINE.encode([0x11; PBKDF2_SALT_LEN]),
        aead: AES_GCM_AEAD_ID.to_string(),
        nonce: BASE64_ENGINE.encode([0x22; AES_GCM_NONCE_LEN]),
        ciphertext: BASE64_ENGINE.encode([ciphertext_byte; 64]),
    }
}

#[test]
fn test_portable_key_ct_eq_identical_keys_returns_equal() {
    let ts = ct_fixture_ts();
    let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    assert!(bool::from(a.ct_eq(&b)));
}

#[test]
fn test_portable_key_ct_eq_different_key_data_returns_not_equal() {
    let ts = ct_fixture_ts();
    let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xCD, ts);
    assert!(!bool::from(a.ct_eq(&b)));
}

#[test]
fn test_portable_key_ct_eq_different_algorithm_returns_not_equal() {
    let ts = ct_fixture_ts();
    let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    let b = ct_fixture_key(KeyAlgorithm::MlKem512, KeyType::Public, 0xAB, ts);
    assert!(!bool::from(a.ct_eq(&b)));
}

#[test]
fn test_portable_key_ct_eq_different_key_type_returns_not_equal() {
    let ts = ct_fixture_ts();
    let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Secret, 0xAB, ts);
    assert!(!bool::from(a.ct_eq(&b)));
}

#[test]
fn test_portable_key_ct_eq_different_created_returns_not_equal() {
    let ts_a = ct_fixture_ts();
    let ts_b = DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z").unwrap().with_timezone(&Utc);
    let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts_a);
    let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts_b);
    assert!(!bool::from(a.ct_eq(&b)));
}

#[test]
fn test_portable_key_ct_eq_different_metadata_returns_not_equal() {
    let ts = ct_fixture_ts();
    let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    let mut b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
    b.set_metadata("tenant".to_string(), serde_json::json!("acme")).unwrap();
    assert!(!bool::from(a.ct_eq(&b)));
}

#[test]
fn test_key_data_ct_eq_variant_mismatch_returns_not_equal() {
    let single = KeyData::from_raw(&[0xAB; 32]);
    let composite = KeyData::Composite {
        pq: BASE64_ENGINE.encode([0xAB; 32]),
        classical: BASE64_ENGINE.encode([0xAB; 32]),
    };
    assert!(!bool::from(single.ct_eq(&composite)));
}

#[test]
fn test_key_data_ct_eq_encrypted_identical_returns_equal() {
    let a = ct_fixture_encrypted(0xEE);
    let b = ct_fixture_encrypted(0xEE);
    assert!(bool::from(a.ct_eq(&b)));
}

#[test]
fn test_key_data_ct_eq_encrypted_different_ciphertext_returns_not_equal() {
    let a = ct_fixture_encrypted(0xEE);
    let b = ct_fixture_encrypted(0xFF);
    assert!(!bool::from(a.ct_eq(&b)));
}

#[test]
fn test_key_data_ct_eq_encrypted_different_envelope_params_returns_not_equal() {
    let a = ct_fixture_encrypted(0xEE);
    let b = KeyData::Encrypted {
        enc: ENCRYPTED_ENVELOPE_VERSION,
        kdf: PBKDF2_KDF_ID.to_string(),
        kdf_iterations: PBKDF2_DEFAULT_ITERATIONS + 100_000,
        kdf_salt: BASE64_ENGINE.encode([0x11; PBKDF2_SALT_LEN]),
        aead: AES_GCM_AEAD_ID.to_string(),
        nonce: BASE64_ENGINE.encode([0x22; AES_GCM_NONCE_LEN]),
        ciphertext: BASE64_ENGINE.encode([0xEE; 64]),
    };
    assert!(!bool::from(a.ct_eq(&b)));
}
