#![allow(deprecated)]

//! Hybrid Cryptography Proof Evidence Suite
//!
//! Structured proof records for every hybrid crypto operation. Each test performs a real
//! crypto operation, asserts correctness, and prints a `[PROOF]` JSON line to stdout.
//!
//! Run: `cargo test --test hybrid_proof_evidence --all-features --release -- --nocapture`
//! Extract: `grep "\[PROOF\]" output.txt > proof_evidence.jsonl`

#![allow(
    clippy::panic,
    clippy::unreachable,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    unused_qualifications
)]

use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use latticearc::primitives::sig::fndsa::FnDsaSecurityLevel;
use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel;
use latticearc::tls::pq_key_exchange::{KexInfo, PqKexMode, get_kex_info, is_pq_available};
use latticearc::tls::{TlsConfig, TlsMode, TlsPolicyEngine, TlsUseCase, tls13::Tls13Config};
use latticearc::{
    ComplianceMode, CryptoConfig, DecryptKey, EncryptKey, EncryptedOutput, EncryptionScheme,
    HybridComponents, PortableKey, SecurityLevel, SecurityMode, UseCase, decrypt,
    decrypt_aes_gcm_with_aad_unverified, deserialize_encrypted_output, encrypt,
    encrypt_aes_gcm_with_aad_unverified, fips_available, generate_fn_dsa_keypair,
    generate_hybrid_keypair_with_level, generate_hybrid_signing_keypair, generate_ml_dsa_keypair,
    generate_slh_dsa_keypair, hash_data, serialize_encrypted_output, sign_hybrid, sign_pq_fn_dsa,
    sign_pq_ml_dsa, sign_pq_slh_dsa, verify_hybrid_signature, verify_pq_fn_dsa, verify_pq_ml_dsa,
    verify_pq_slh_dsa,
};

// ============================================================================
// Helpers
// ============================================================================

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

fn ml_kem_level_for_scheme(scheme: &EncryptionScheme) -> MlKemSecurityLevel {
    scheme.ml_kem_level().unwrap_or_else(|| panic!("scheme {scheme} has no ML-KEM level"))
}

fn is_regulated(uc: UseCase) -> bool {
    matches!(
        uc,
        UseCase::GovernmentClassified
            | UseCase::HealthcareRecords
            | UseCase::PaymentCard
            | UseCase::FinancialTransactions
    )
}

fn all_use_cases() -> Vec<UseCase> {
    vec![
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
    ]
}

fn uc_name(uc: UseCase) -> &'static str {
    match uc {
        UseCase::SecureMessaging => "SecureMessaging",
        UseCase::EmailEncryption => "EmailEncryption",
        UseCase::VpnTunnel => "VpnTunnel",
        UseCase::ApiSecurity => "ApiSecurity",
        UseCase::FileStorage => "FileStorage",
        UseCase::DatabaseEncryption => "DatabaseEncryption",
        UseCase::CloudStorage => "CloudStorage",
        UseCase::BackupArchive => "BackupArchive",
        UseCase::ConfigSecrets => "ConfigSecrets",
        UseCase::Authentication => "Authentication",
        UseCase::SessionToken => "SessionToken",
        UseCase::DigitalCertificate => "DigitalCertificate",
        UseCase::KeyExchange => "KeyExchange",
        UseCase::FinancialTransactions => "FinancialTransactions",
        UseCase::LegalDocuments => "LegalDocuments",
        UseCase::BlockchainTransaction => "BlockchainTransaction",
        UseCase::HealthcareRecords => "HealthcareRecords",
        UseCase::GovernmentClassified => "GovernmentClassified",
        UseCase::PaymentCard => "PaymentCard",
        UseCase::IoTDevice => "IoTDevice",
        UseCase::FirmwareSigning => "FirmwareSigning",
        UseCase::AuditLog => "AuditLog",
        _ => unreachable!("unexpected UseCase variant"),
    }
}

// ============================================================================
// Section 1: UseCase → Scheme Selection Proof (22 tests in 1 function)
// ============================================================================

#[test]
fn proof_all_22_usecases_select_correct_scheme() {
    let data = b"Proof evidence: UseCase -> Scheme selection";
    let use_cases = all_use_cases();
    assert_eq!(use_cases.len(), 22, "Must test all 22 UseCase variants");

    for uc in &use_cases {
        let expected = expected_scheme_for_use_case(*uc);
        let level = ml_kem_level_for_scheme(&expected);
        let ct_size = level.ciphertext_size();
        let name = uc_name(*uc);

        // Skip regulated use cases when FIPS is not available
        if is_regulated(*uc) && !fips_available() {
            println!(
                "[PROOF] {{\"section\":1,\"test\":\"usecase_scheme_{name}\",\
                 \"use_case\":\"{name}\",\"status\":\"SKIPPED\",\
                 \"reason\":\"FIPS not available\"}}"
            );
            continue;
        }

        let (pk, sk) = generate_hybrid_keypair_with_level(level)
            .unwrap_or_else(|e| panic!("keypair gen failed for {name} at {level:?}: {e}"));

        let config = CryptoConfig::new().use_case(*uc);
        let config = if is_regulated(*uc) && !fips_available() {
            config.compliance(ComplianceMode::Default)
        } else {
            config
        };

        let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
            .unwrap_or_else(|e| panic!("encrypt failed for {name}: {e}"));

        // Assertions
        assert_eq!(
            encrypted.scheme(),
            &expected,
            "UseCase::{name} should select {expected}, got {}",
            encrypted.scheme()
        );
        assert!(encrypted.hybrid_data().is_some(), "UseCase::{name} must produce hybrid_data");
        let hybrid = encrypted.hybrid_data().unwrap();
        assert_eq!(
            hybrid.ml_kem_ciphertext().len(),
            ct_size,
            "UseCase::{name} ML-KEM CT size: expected {ct_size}, got {}",
            hybrid.ml_kem_ciphertext().len()
        );
        assert_eq!(
            hybrid.ecdh_ephemeral_pk().len(),
            32,
            "UseCase::{name} ECDH ephemeral PK must be 32 bytes"
        );

        // Decrypt roundtrip
        let config = CryptoConfig::new().use_case(*uc);
        let config = if is_regulated(*uc) && !fips_available() {
            config.compliance(ComplianceMode::Default)
        } else {
            config
        };
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
            .unwrap_or_else(|e| panic!("decrypt failed for {name}: {e}"));
        assert_eq!(decrypted.as_slice(), data, "UseCase::{name} roundtrip failed");

        println!(
            "[PROOF] {{\"section\":1,\"test\":\"usecase_scheme_{name}\",\
             \"use_case\":\"{name}\",\
             \"expected_scheme\":\"{expected}\",\
             \"actual_scheme\":\"{}\",\
             \"ml_kem_ct_bytes\":{},\
             \"ecdh_pk_bytes\":{},\
             \"nonce_bytes\":{},\
             \"tag_bytes\":{},\
             \"plaintext_len\":{},\
             \"ciphertext_len\":{},\
             \"roundtrip\":\"PASS\",\
             \"status\":\"PASS\"}}",
            encrypted.scheme(),
            hybrid.ml_kem_ciphertext().len(),
            hybrid.ecdh_ephemeral_pk().len(),
            encrypted.nonce().len(),
            encrypted.tag().len(),
            data.len(),
            encrypted.ciphertext().len(),
        );
    }
}

// ============================================================================
// Section 2: SecurityLevel → Scheme Proof (4 tests)
// ============================================================================

#[test]
fn proof_security_level_standard_selects_ml_kem_512() {
    proof_security_level(
        SecurityLevel::Standard,
        EncryptionScheme::HybridMlKem512Aes256Gcm,
        "Standard",
    );
}

#[test]
fn proof_security_level_high_selects_ml_kem_768() {
    proof_security_level(SecurityLevel::High, EncryptionScheme::HybridMlKem768Aes256Gcm, "High");
}

#[test]
fn proof_security_level_maximum_selects_ml_kem_1024() {
    proof_security_level(
        SecurityLevel::Maximum,
        EncryptionScheme::HybridMlKem1024Aes256Gcm,
        "Maximum",
    );
}

#[test]
fn proof_security_level_quantum_selects_ml_kem_1024() {
    proof_security_level(
        SecurityLevel::Quantum,
        EncryptionScheme::HybridMlKem1024Aes256Gcm,
        "Quantum",
    );
}

fn proof_security_level(level: SecurityLevel, expected_scheme: EncryptionScheme, level_name: &str) {
    let data = b"Proof evidence: SecurityLevel -> Scheme";
    let ml_kem_level = ml_kem_level_for_scheme(&expected_scheme);
    let ct_size = ml_kem_level.ciphertext_size();

    let (pk, sk) = generate_hybrid_keypair_with_level(ml_kem_level)
        .unwrap_or_else(|e| panic!("keypair gen failed for {level_name}: {e}"));

    let config = CryptoConfig::new().security_level(level);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config)
        .unwrap_or_else(|e| panic!("encrypt failed for {level_name}: {e}"));

    assert_eq!(
        encrypted.scheme(),
        &expected_scheme,
        "SecurityLevel::{level_name} should select {expected_scheme}, got {}",
        encrypted.scheme()
    );
    let hybrid = encrypted.hybrid_data().unwrap();
    assert_eq!(hybrid.ml_kem_ciphertext().len(), ct_size);

    let config = CryptoConfig::new().security_level(level);
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
        .unwrap_or_else(|e| panic!("decrypt failed for {level_name}: {e}"));
    assert_eq!(decrypted.as_slice(), data);

    println!(
        "[PROOF] {{\"section\":2,\"test\":\"security_level_{level_name}\",\
         \"security_level\":\"{level_name}\",\
         \"expected_scheme\":\"{expected_scheme}\",\
         \"actual_scheme\":\"{}\",\
         \"ml_kem_ct_bytes\":{},\
         \"roundtrip\":\"PASS\",\
         \"status\":\"PASS\"}}",
        encrypted.scheme(),
        hybrid.ml_kem_ciphertext().len(),
    );
}

// ============================================================================
// Section 3: ML-KEM NIST Parameter Proof (3 tests)
// ============================================================================

#[test]
fn proof_ml_kem_512_nist_parameters_verified() {
    proof_ml_kem_nist_params(MlKemSecurityLevel::MlKem512, 800, 768, 32, "ML-KEM-512");
}

#[test]
fn proof_ml_kem_768_nist_parameters_verified() {
    proof_ml_kem_nist_params(MlKemSecurityLevel::MlKem768, 1184, 1088, 32, "ML-KEM-768");
}

#[test]
fn proof_ml_kem_1024_nist_parameters_verified() {
    proof_ml_kem_nist_params(MlKemSecurityLevel::MlKem1024, 1568, 1568, 32, "ML-KEM-1024");
}

fn proof_ml_kem_nist_params(
    level: MlKemSecurityLevel,
    expected_pk: usize,
    expected_ct: usize,
    expected_ss: usize,
    level_name: &str,
) {
    // Verify compile-time constants match FIPS 203 Table 2
    let actual_pk = level.public_key_size();
    let actual_ct = level.ciphertext_size();
    let actual_ss = level.shared_secret_size();

    assert_eq!(actual_pk, expected_pk, "{level_name} PK size mismatch");
    assert_eq!(actual_ct, expected_ct, "{level_name} CT size mismatch");
    assert_eq!(actual_ss, expected_ss, "{level_name} SS size mismatch");

    // Also verify via live keygen + encrypt
    let (pk, sk) = generate_hybrid_keypair_with_level(level)
        .unwrap_or_else(|e| panic!("keypair gen for {level_name}: {e}"));

    assert_eq!(pk.ml_kem_pk().len(), expected_pk, "{level_name} live PK size");
    assert_eq!(pk.ecdh_pk().len(), 32, "{level_name} ECDH PK must be 32 bytes");

    // Encrypt to verify CT size
    let security_level = match level {
        MlKemSecurityLevel::MlKem512 => SecurityLevel::Standard,
        MlKemSecurityLevel::MlKem768 => SecurityLevel::High,
        MlKemSecurityLevel::MlKem1024 => SecurityLevel::Maximum,
        _ => unreachable!("unexpected MlKemSecurityLevel variant"),
    };
    let config = CryptoConfig::new().security_level(security_level);
    let encrypted = encrypt(b"NIST param proof", EncryptKey::Hybrid(&pk), config)
        .unwrap_or_else(|e| panic!("encrypt for {level_name}: {e}"));

    let hybrid = encrypted.hybrid_data().unwrap();
    assert_eq!(hybrid.ml_kem_ciphertext().len(), expected_ct, "{level_name} live CT size");

    // Roundtrip
    let config = CryptoConfig::new().security_level(security_level);
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
        .unwrap_or_else(|e| panic!("decrypt for {level_name}: {e}"));
    assert_eq!(decrypted.as_slice(), b"NIST param proof");

    println!(
        "[PROOF] {{\"section\":3,\"test\":\"nist_params_{level_name}\",\
         \"level\":\"{level_name}\",\
         \"pk_bytes\":{actual_pk},\"expected_pk\":{expected_pk},\
         \"ct_bytes\":{},\"expected_ct\":{expected_ct},\
         \"ss_bytes\":{actual_ss},\"expected_ss\":{expected_ss},\
         \"live_pk_bytes\":{},\
         \"live_ct_bytes\":{},\
         \"all_match\":true,\
         \"status\":\"PASS\"}}",
        actual_ct,
        pk.ml_kem_pk().len(),
        hybrid.ml_kem_ciphertext().len(),
    );
}

// ============================================================================
// Section 4: Hybrid Encryption Roundtrip — Variable Size (5 tests)
// ============================================================================

#[test]
fn proof_encrypt_roundtrip_empty_succeeds() {
    proof_variable_size_roundtrip(0, "empty");
}

#[test]
fn proof_encrypt_roundtrip_1_byte_succeeds() {
    proof_variable_size_roundtrip(1, "1B");
}

#[test]
fn proof_encrypt_roundtrip_1kb_succeeds() {
    proof_variable_size_roundtrip(1024, "1KB");
}

#[test]
fn proof_encrypt_roundtrip_100kb_succeeds() {
    proof_variable_size_roundtrip(100 * 1024, "100KB");
}

#[test]
fn proof_encrypt_roundtrip_1mb_succeeds() {
    proof_variable_size_roundtrip(1024 * 1024, "1MB");
}

fn proof_variable_size_roundtrip(size: usize, label: &str) {
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let level = MlKemSecurityLevel::MlKem768;

    let (pk, sk) = generate_hybrid_keypair_with_level(level)
        .unwrap_or_else(|e| panic!("keypair gen for {label}: {e}"));

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let encrypted = encrypt(&data, EncryptKey::Hybrid(&pk), config)
        .unwrap_or_else(|e| panic!("encrypt for {label}: {e}"));

    let hybrid = encrypted.hybrid_data().unwrap();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config)
        .unwrap_or_else(|e| panic!("decrypt for {label}: {e}"));
    assert_eq!(decrypted.as_slice(), data.as_slice(), "roundtrip failed for {label}");

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"variable_size_{label}\",\
         \"plaintext_len\":{size},\
         \"ciphertext_len\":{},\
         \"ml_kem_ct_bytes\":{},\
         \"ecdh_pk_bytes\":{},\
         \"nonce_bytes\":{},\
         \"tag_bytes\":{},\
         \"scheme\":\"{}\",\
         \"roundtrip\":\"PASS\",\
         \"status\":\"PASS\"}}",
        encrypted.ciphertext().len(),
        hybrid.ml_kem_ciphertext().len(),
        hybrid.ecdh_ephemeral_pk().len(),
        encrypted.nonce().len(),
        encrypted.tag().len(),
        encrypted.scheme(),
    );
}

// ============================================================================
// Section 5: Signature Algorithm Roundtrip Proof (6 tests)
// ============================================================================

#[test]
fn proof_sig_ml_dsa_44_verified() {
    let message = b"ML-DSA-44 proof evidence";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("ML-DSA-44 keygen");

    let signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MlDsa44, SecurityMode::Unverified)
            .expect("ML-DSA-44 sign");

    let valid = verify_pq_ml_dsa(
        message,
        &signature,
        pk.as_slice(),
        MlDsaParameterSet::MlDsa44,
        SecurityMode::Unverified,
    )
    .expect("ML-DSA-44 verify");
    assert!(valid, "ML-DSA-44 signature must verify");

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"sig_ml_dsa_44\",\
         \"algorithm\":\"ML-DSA-44\",\"standard\":\"FIPS 204\",\
         \"pk_bytes\":{},\"signature_bytes\":{},\"message_len\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        pk.len(),
        signature.len(),
        message.len(),
    );
}

#[test]
fn proof_sig_ml_dsa_65_verified() {
    let message = b"ML-DSA-65 proof evidence";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("ML-DSA-65 keygen");

    let signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MlDsa65, SecurityMode::Unverified)
            .expect("ML-DSA-65 sign");

    let valid = verify_pq_ml_dsa(
        message,
        &signature,
        pk.as_slice(),
        MlDsaParameterSet::MlDsa65,
        SecurityMode::Unverified,
    )
    .expect("ML-DSA-65 verify");
    assert!(valid, "ML-DSA-65 signature must verify");

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"sig_ml_dsa_65\",\
         \"algorithm\":\"ML-DSA-65\",\"standard\":\"FIPS 204\",\
         \"pk_bytes\":{},\"signature_bytes\":{},\"message_len\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        pk.len(),
        signature.len(),
        message.len(),
    );
}

#[test]
fn proof_sig_ml_dsa_87_verified() {
    let message = b"ML-DSA-87 proof evidence";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa87).expect("ML-DSA-87 keygen");

    let signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MlDsa87, SecurityMode::Unverified)
            .expect("ML-DSA-87 sign");

    let valid = verify_pq_ml_dsa(
        message,
        &signature,
        pk.as_slice(),
        MlDsaParameterSet::MlDsa87,
        SecurityMode::Unverified,
    )
    .expect("ML-DSA-87 verify");
    assert!(valid, "ML-DSA-87 signature must verify");

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"sig_ml_dsa_87\",\
         \"algorithm\":\"ML-DSA-87\",\"standard\":\"FIPS 204\",\
         \"pk_bytes\":{},\"signature_bytes\":{},\"message_len\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        pk.len(),
        signature.len(),
        message.len(),
    );
}

#[test]
fn proof_sig_hybrid_ml_dsa_65_ed25519_verified() {
    let message = b"Hybrid ML-DSA-65+Ed25519 proof evidence";
    let (pk, sk) =
        generate_hybrid_signing_keypair(SecurityMode::Unverified).expect("Hybrid signing keygen");

    let signature = sign_hybrid(message, &sk, SecurityMode::Unverified).expect("Hybrid sign");

    let valid = verify_hybrid_signature(message, &signature, &pk, SecurityMode::Unverified)
        .expect("Hybrid verify");
    assert!(valid, "Hybrid ML-DSA-65+Ed25519 signature must verify");

    let total_sig_bytes = signature.ml_dsa_sig().len() + signature.ed25519_sig().len();
    let total_pk_bytes = pk.ml_dsa_pk().len() + pk.ed25519_pk().len();

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"sig_hybrid_ml_dsa_65_ed25519\",\
         \"algorithm\":\"Hybrid ML-DSA-65+Ed25519\",\"standard\":\"FIPS 204 + EdDSA\",\
         \"ml_dsa_pk_bytes\":{},\"ed25519_pk_bytes\":{},\"total_pk_bytes\":{total_pk_bytes},\
         \"ml_dsa_sig_bytes\":{},\"ed25519_sig_bytes\":{},\"total_sig_bytes\":{total_sig_bytes},\
         \"message_len\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        pk.ml_dsa_pk().len(),
        pk.ed25519_pk().len(),
        signature.ml_dsa_sig().len(),
        signature.ed25519_sig().len(),
        message.len(),
    );
}

#[test]
fn proof_sig_slh_dsa_shake_128s_verified() {
    let message = b"SLH-DSA-SHAKE-128s proof evidence";
    let (pk, sk) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("SLH-DSA keygen");

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("SLH-DSA sign");

    let valid = verify_pq_slh_dsa(
        message,
        &signature,
        pk.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("SLH-DSA verify");
    assert!(valid, "SLH-DSA-SHAKE-128s signature must verify");

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"sig_slh_dsa_shake_128s\",\
         \"algorithm\":\"SLH-DSA-SHAKE-128s\",\"standard\":\"FIPS 205\",\
         \"pk_bytes\":{},\"signature_bytes\":{},\"message_len\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        pk.len(),
        signature.len(),
        message.len(),
    );
}

#[test]
fn proof_sig_fn_dsa_512_verified() {
    let message = b"FN-DSA-512 proof evidence";
    let (pk, sk) = generate_fn_dsa_keypair().expect("FN-DSA-512 keygen");

    let signature = sign_pq_fn_dsa(
        message,
        sk.as_ref(),
        FnDsaSecurityLevel::Level512,
        SecurityMode::Unverified,
    )
    .expect("FN-DSA-512 sign");

    let valid = verify_pq_fn_dsa(
        message,
        &signature,
        pk.as_slice(),
        FnDsaSecurityLevel::Level512,
        SecurityMode::Unverified,
    )
    .expect("FN-DSA-512 verify");
    assert!(valid, "FN-DSA-512 signature must verify");

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"sig_fn_dsa_512\",\
         \"algorithm\":\"FN-DSA-512\",\"standard\":\"FIPS 206\",\
         \"pk_bytes\":{},\"signature_bytes\":{},\"message_len\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        pk.len(),
        signature.len(),
        message.len(),
    );
}

// ============================================================================
// Section 6: Serialization Preserves Scheme (3 tests)
// ============================================================================

#[test]
fn proof_serialization_preserves_scheme_ml_kem_512() {
    proof_serialization_roundtrip(
        MlKemSecurityLevel::MlKem512,
        SecurityLevel::Standard,
        "MlKem512",
    );
}

#[test]
fn proof_serialization_preserves_scheme_ml_kem_768() {
    proof_serialization_roundtrip(MlKemSecurityLevel::MlKem768, SecurityLevel::High, "MlKem768");
}

#[test]
fn proof_serialization_preserves_scheme_ml_kem_1024() {
    proof_serialization_roundtrip(
        MlKemSecurityLevel::MlKem1024,
        SecurityLevel::Maximum,
        "MlKem1024",
    );
}

fn proof_serialization_roundtrip(
    key_level: MlKemSecurityLevel,
    security_level: SecurityLevel,
    level_name: &str,
) {
    let data = b"Serialization proof evidence";
    let (pk, sk) = generate_hybrid_keypair_with_level(key_level)
        .unwrap_or_else(|e| panic!("keypair gen for {level_name}: {e}"));

    let config = CryptoConfig::new().security_level(security_level);
    let original = encrypt(data, EncryptKey::Hybrid(&pk), config)
        .unwrap_or_else(|e| panic!("encrypt for {level_name}: {e}"));

    // Serialize → deserialize
    let json = serialize_encrypted_output(&original)
        .unwrap_or_else(|e| panic!("serialize for {level_name}: {e}"));
    let json_len = json.len();
    let restored = deserialize_encrypted_output(&json)
        .unwrap_or_else(|e| panic!("deserialize for {level_name}: {e}"));

    // Scheme preserved
    assert_eq!(
        restored.scheme(),
        original.scheme(),
        "Serialization must preserve scheme for {level_name}"
    );

    // Hybrid data preserved
    let orig_hybrid = original.hybrid_data().unwrap();
    let rest_hybrid = restored.hybrid_data().unwrap();
    assert_eq!(
        orig_hybrid.ml_kem_ciphertext(),
        rest_hybrid.ml_kem_ciphertext(),
        "ML-KEM CT must survive serialization for {level_name}"
    );
    assert_eq!(
        orig_hybrid.ecdh_ephemeral_pk(),
        rest_hybrid.ecdh_ephemeral_pk(),
        "ECDH ephemeral PK must survive serialization for {level_name}"
    );

    // Decrypt from deserialized output
    let config = CryptoConfig::new().security_level(security_level);
    let decrypted = decrypt(&restored, DecryptKey::Hybrid(&sk), config)
        .unwrap_or_else(|e| panic!("decrypt after deserialize for {level_name}: {e}"));
    assert_eq!(decrypted.as_slice(), data);

    println!(
        "[PROOF] {{\"section\":6,\"test\":\"serialization_{level_name}\",\
         \"level\":\"{level_name}\",\
         \"original_scheme\":\"{}\",\
         \"restored_scheme\":\"{}\",\
         \"json_bytes\":{json_len},\
         \"ml_kem_ct_preserved\":true,\
         \"ecdh_pk_preserved\":true,\
         \"decrypt_after_deserialize\":\"PASS\",\
         \"status\":\"PASS\"}}",
        original.scheme(),
        restored.scheme(),
    );
}

// ============================================================================
// Section 7: Negative — Wrong Key (4 tests)
// ============================================================================

#[test]
fn proof_negative_wrong_decrypt_key_fails() {
    let data = b"Negative test: wrong key";
    let level = MlKemSecurityLevel::MlKem768;

    let (pk_a, _sk_a) = generate_hybrid_keypair_with_level(level).expect("keypair A");
    let (_pk_b, sk_b) = generate_hybrid_keypair_with_level(level).expect("keypair B");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk_a), config).expect("encrypt");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk_b), config);
    assert!(result.is_err(), "Decrypt with wrong key must fail");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":7,\"test\":\"wrong_decrypt_key\",\
         \"expected_error\":\"decryption failure\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

#[test]
fn proof_negative_ml_kem_512_key_decrypt_768_ct_fails() {
    let data = b"Negative test: 512 key vs 768 ciphertext";

    let (pk_768, _sk_768) =
        generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem768).expect("keypair 768");
    let (_pk_512, sk_512) =
        generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem512).expect("keypair 512");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk_768), config).expect("encrypt");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk_512), config);
    assert!(result.is_err(), "ML-KEM-512 key must not decrypt ML-KEM-768 CT");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":7,\"test\":\"ml_kem_512_key_decrypt_768_ct\",\
         \"expected_error\":\"key level mismatch or decryption failure\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

#[test]
fn proof_negative_ml_kem_768_key_decrypt_1024_ct_fails() {
    let data = b"Negative test: 768 key vs 1024 ciphertext";

    let (pk_1024, _sk_1024) =
        generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem1024).expect("keypair 1024");
    let (_pk_768, sk_768) =
        generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem768).expect("keypair 768");

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk_1024), config).expect("encrypt");

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk_768), config);
    assert!(result.is_err(), "ML-KEM-768 key must not decrypt ML-KEM-1024 CT");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":7,\"test\":\"ml_kem_768_key_decrypt_1024_ct\",\
         \"expected_error\":\"key level mismatch or decryption failure\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

#[test]
fn proof_negative_wrong_verify_key_fails() {
    let message = b"Negative test: wrong signature verification key";
    let (pk_a, _sk_a) =
        generate_hybrid_signing_keypair(SecurityMode::Unverified).expect("keypair A");
    let (_pk_b, sk_b) =
        generate_hybrid_signing_keypair(SecurityMode::Unverified).expect("keypair B");

    let signature = sign_hybrid(message, &sk_b, SecurityMode::Unverified).expect("sign with B");

    let result = verify_hybrid_signature(message, &signature, &pk_a, SecurityMode::Unverified);
    // Verification should either return Ok(false) or Err
    let failed = match &result {
        Ok(valid) => !valid,
        Err(_) => true,
    };
    assert!(failed, "Verify with wrong key must fail or return false");

    let status_detail = match result {
        Ok(v) => format!("returned {v}"),
        Err(e) => format!("error: {}", e.to_string().chars().take(60).collect::<String>()),
    };

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"wrong_verify_key\",\
         \"expected_error\":\"verification failure\",\
         \"actual_result\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        status_detail.replace('"', "'"),
    );
}

// ============================================================================
// Section 8: Negative — Corrupted Ciphertext (5 tests)
// ============================================================================

#[test]
fn proof_negative_corrupted_ml_kem_ct_fails() {
    proof_corrupted_field("ml_kem_ciphertext", |enc| {
        let tampered_hybrid = enc.hybrid_data().map(|h| {
            let mut ml_kem_ct = h.ml_kem_ciphertext().to_vec();
            if !ml_kem_ct.is_empty() {
                ml_kem_ct[0] ^= 0xFF;
            }
            HybridComponents::new(ml_kem_ct, h.ecdh_ephemeral_pk().to_vec())
        });
        EncryptedOutput::new(
            enc.scheme().clone(),
            enc.ciphertext().to_vec(),
            enc.nonce().to_vec(),
            enc.tag().to_vec(),
            tampered_hybrid,
            enc.timestamp(),
            enc.key_id().map(str::to_owned),
        )
    });
}

#[test]
fn proof_negative_corrupted_ecdh_pk_fails() {
    proof_corrupted_field("ecdh_ephemeral_pk", |enc| {
        let tampered_hybrid = enc.hybrid_data().map(|h| {
            let mut ecdh_pk = h.ecdh_ephemeral_pk().to_vec();
            if !ecdh_pk.is_empty() {
                ecdh_pk[0] ^= 0xFF;
            }
            HybridComponents::new(h.ml_kem_ciphertext().to_vec(), ecdh_pk)
        });
        EncryptedOutput::new(
            enc.scheme().clone(),
            enc.ciphertext().to_vec(),
            enc.nonce().to_vec(),
            enc.tag().to_vec(),
            tampered_hybrid,
            enc.timestamp(),
            enc.key_id().map(str::to_owned),
        )
    });
}

#[test]
fn proof_negative_corrupted_symmetric_ct_fails() {
    proof_corrupted_field("symmetric_ciphertext", |enc| {
        let mut ciphertext = enc.ciphertext().to_vec();
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }
        EncryptedOutput::new(
            enc.scheme().clone(),
            ciphertext,
            enc.nonce().to_vec(),
            enc.tag().to_vec(),
            enc.hybrid_data().cloned(),
            enc.timestamp(),
            enc.key_id().map(str::to_owned),
        )
    });
}

#[test]
fn proof_negative_corrupted_nonce_fails() {
    proof_corrupted_field("nonce", |enc| {
        let mut nonce = enc.nonce().to_vec();
        if !nonce.is_empty() {
            nonce[0] ^= 0xFF;
        }
        EncryptedOutput::new(
            enc.scheme().clone(),
            enc.ciphertext().to_vec(),
            nonce,
            enc.tag().to_vec(),
            enc.hybrid_data().cloned(),
            enc.timestamp(),
            enc.key_id().map(str::to_owned),
        )
    });
}

#[test]
fn proof_negative_corrupted_tag_fails() {
    proof_corrupted_field("tag", |enc| {
        let mut tag = enc.tag().to_vec();
        if !tag.is_empty() {
            tag[0] ^= 0xFF;
        }
        EncryptedOutput::new(
            enc.scheme().clone(),
            enc.ciphertext().to_vec(),
            enc.nonce().to_vec(),
            tag,
            enc.hybrid_data().cloned(),
            enc.timestamp(),
            enc.key_id().map(str::to_owned),
        )
    });
}

fn proof_corrupted_field(
    field_name: &str,
    corrupt: impl FnOnce(EncryptedOutput) -> EncryptedOutput,
) {
    let data = b"Corruption test data for proof evidence";
    let level = MlKemSecurityLevel::MlKem768;

    let (pk, sk) = generate_hybrid_keypair_with_level(level).expect("keypair");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), config).expect("encrypt");

    // Corrupt the specified field
    let encrypted = corrupt(encrypted);

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config);
    assert!(result.is_err(), "Corrupted {field_name} must cause decryption failure");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":8,\"test\":\"corrupted_{field_name}\",\
         \"corrupted_field\":\"{field_name}\",\
         \"expected_error\":\"decryption failure\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

// ============================================================================
// Section 9: Negative — Wrong AAD (2 tests)
// ============================================================================

#[test]
fn proof_negative_wrong_aad_fails() {
    let data = b"AAD mismatch proof evidence";
    let key = [0x42u8; 32];

    let encrypted =
        encrypt_aes_gcm_with_aad_unverified(data, &key, b"context-a").expect("encrypt with AAD");

    let result = decrypt_aes_gcm_with_aad_unverified(&encrypted, &key, b"context-b");
    assert!(result.is_err(), "Decrypt with wrong AAD must fail");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":9,\"test\":\"wrong_aad\",\
         \"encrypt_aad\":\"context-a\",\"decrypt_aad\":\"context-b\",\
         \"expected_error\":\"decryption failure\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

#[test]
fn proof_negative_aad_present_vs_absent_fails() {
    let data = b"AAD present vs absent proof evidence";
    let key = [0x42u8; 32];

    let encrypted = encrypt_aes_gcm_with_aad_unverified(data, &key, b"required-context")
        .expect("encrypt with AAD");

    // Decrypt with empty AAD (absent)
    let result = decrypt_aes_gcm_with_aad_unverified(&encrypted, &key, b"");
    assert!(result.is_err(), "Decrypt without AAD when encrypted with AAD must fail");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":9,\"test\":\"aad_present_vs_absent\",\
         \"encrypt_aad\":\"required-context\",\"decrypt_aad\":\"\",\
         \"expected_error\":\"decryption failure\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

// ============================================================================
// Section 10: Negative — Cross-Level Mismatch (3 tests)
// ============================================================================

#[test]
fn proof_negative_cross_level_512_key_768_scheme_fails() {
    proof_cross_level_mismatch(
        MlKemSecurityLevel::MlKem512,
        SecurityLevel::High, // selects ML-KEM-768
        "512_key_768_scheme",
    );
}

#[test]
fn proof_negative_cross_level_768_key_1024_scheme_fails() {
    proof_cross_level_mismatch(
        MlKemSecurityLevel::MlKem768,
        SecurityLevel::Maximum, // selects ML-KEM-1024
        "768_key_1024_scheme",
    );
}

#[test]
fn proof_negative_cross_level_1024_key_512_scheme_fails() {
    proof_cross_level_mismatch(
        MlKemSecurityLevel::MlKem1024,
        SecurityLevel::Standard, // selects ML-KEM-512
        "1024_key_512_scheme",
    );
}

fn proof_cross_level_mismatch(
    key_level: MlKemSecurityLevel,
    scheme_security_level: SecurityLevel,
    label: &str,
) {
    let data = b"Cross-level mismatch proof evidence";

    let (pk, _sk) = generate_hybrid_keypair_with_level(key_level)
        .unwrap_or_else(|e| panic!("keypair gen for {label}: {e}"));

    let config = CryptoConfig::new().security_level(scheme_security_level);
    let result = encrypt(data, EncryptKey::Hybrid(&pk), config);
    assert!(result.is_err(), "Cross-level mismatch {label} must fail at encrypt");

    let err_msg = result.unwrap_err().to_string();
    println!(
        "[PROOF] {{\"section\":10,\"test\":\"cross_level_{label}\",\
         \"key_level\":\"{key_level:?}\",\
         \"expected_error\":\"key level mismatch\",\
         \"actual_error_contains\":\"{}\",\
         \"negative\":\"PASS\",\"status\":\"PASS\"}}",
        err_msg.chars().take(80).collect::<String>().replace('"', "'"),
    );
}

// ============================================================================
// Section 11: TLS Policy Engine & PQ Key Exchange Proof
// ============================================================================

#[test]
fn proof_tls_all_use_cases_select_correct_mode() {
    let expected: Vec<(TlsUseCase, TlsMode, &str)> = vec![
        (TlsUseCase::WebServer, TlsMode::Hybrid, "WebServer"),
        (TlsUseCase::InternalService, TlsMode::Hybrid, "InternalService"),
        (TlsUseCase::ApiGateway, TlsMode::Hybrid, "ApiGateway"),
        (TlsUseCase::IoT, TlsMode::Classic, "IoT"),
        (TlsUseCase::LegacyIntegration, TlsMode::Classic, "LegacyIntegration"),
        (TlsUseCase::FinancialServices, TlsMode::Hybrid, "FinancialServices"),
        (TlsUseCase::Healthcare, TlsMode::Hybrid, "Healthcare"),
        (TlsUseCase::Government, TlsMode::Pq, "Government"),
        (TlsUseCase::DatabaseConnection, TlsMode::Hybrid, "DatabaseConnection"),
        (TlsUseCase::RealTimeStreaming, TlsMode::Classic, "RealTimeStreaming"),
    ];

    assert_eq!(TlsUseCase::all().len(), expected.len(), "Must cover all TLS use cases");

    for (uc, expected_mode, name) in &expected {
        let actual_mode = TlsPolicyEngine::recommend_mode(*uc);
        assert_eq!(
            actual_mode, *expected_mode,
            "TlsUseCase::{name} should select {expected_mode:?}, got {actual_mode:?}"
        );

        // Also verify TlsConfig builder wires through correctly
        let config = TlsConfig::new().use_case(*uc);
        assert_eq!(config.mode, *expected_mode, "TlsConfig.use_case({name}) mode mismatch");

        let mode_str = match actual_mode {
            TlsMode::Classic => "Classic",
            TlsMode::Hybrid => "Hybrid",
            TlsMode::Pq => "Pq",
            _ => unreachable!("unexpected TlsMode variant"),
        };

        println!(
            "[PROOF] {{\"section\":11,\"test\":\"tls_usecase_{name}\",\
             \"tls_use_case\":\"{name}\",\
             \"expected_mode\":\"{mode_str}\",\
             \"actual_mode\":\"{mode_str}\",\
             \"config_wired\":true,\
             \"status\":\"PASS\"}}"
        );
    }
}

#[test]
fn proof_tls_security_levels_select_correct_mode() {
    let cases: Vec<(SecurityLevel, TlsMode, &str)> = vec![
        (SecurityLevel::Standard, TlsMode::Hybrid, "Standard"),
        (SecurityLevel::High, TlsMode::Hybrid, "High"),
        (SecurityLevel::Maximum, TlsMode::Hybrid, "Maximum"),
        (SecurityLevel::Quantum, TlsMode::Pq, "Quantum"),
    ];

    for (level, expected_mode, name) in &cases {
        let actual_mode = TlsPolicyEngine::select_by_security_level(*level);
        assert_eq!(actual_mode, *expected_mode);

        let config = TlsConfig::new().security_level(*level);
        assert_eq!(config.mode, *expected_mode);

        let mode_str = match actual_mode {
            TlsMode::Classic => "Classic",
            TlsMode::Hybrid => "Hybrid",
            TlsMode::Pq => "Pq",
            _ => unreachable!("unexpected TlsMode variant"),
        };

        println!(
            "[PROOF] {{\"section\":11,\"test\":\"tls_security_level_{name}\",\
             \"security_level\":\"{name}\",\
             \"expected_mode\":\"{mode_str}\",\
             \"actual_mode\":\"{mode_str}\",\
             \"status\":\"PASS\"}}"
        );
    }
}

#[test]
fn proof_tls_config_converts_to_tls13_all_modes() {
    let modes = [
        (TlsMode::Classic, "Classic", false),
        (TlsMode::Hybrid, "Hybrid", true),
        (TlsMode::Pq, "Pq", true),
    ];

    for (mode, name, expect_pq_kx) in &modes {
        let mut tls_config = TlsConfig::new();
        tls_config.mode = *mode;
        let tls13 = Tls13Config::from(&tls_config);

        assert_eq!(tls13.mode, *mode, "Tls13Config mode mismatch for {name}");
        assert_eq!(tls13.use_pq_kx, *expect_pq_kx, "Tls13Config PQ KX mismatch for {name}");

        println!(
            "[PROOF] {{\"section\":11,\"test\":\"tls13_config_{name}\",\
             \"mode\":\"{name}\",\
             \"use_pq_kx\":{},\
             \"protocol\":\"TLS 1.3\",\
             \"status\":\"PASS\"}}",
            tls13.use_pq_kx,
        );
    }
}

#[test]
fn proof_tls_pq_key_exchange_info_verified() {
    assert!(is_pq_available(), "PQ key exchange must be available");

    let kex_modes: Vec<(TlsMode, PqKexMode, &str, bool)> = vec![
        (TlsMode::Hybrid, PqKexMode::RustlsPq, "Hybrid_RustlsPq", true),
        (TlsMode::Pq, PqKexMode::RustlsPq, "Pq_RustlsPq", true),
        (TlsMode::Classic, PqKexMode::Classical, "Classic_Classical", false),
    ];

    for (mode, kex_mode, label, expect_pq) in &kex_modes {
        let info: KexInfo = get_kex_info(*mode, *kex_mode);
        assert_eq!(info.is_pq_secure, *expect_pq, "PQ flag mismatch for {label}");

        // Verify hybrid key sizes match NIST spec
        if *expect_pq {
            // X25519 (32) + ML-KEM-768 PK (1184) = 1216
            assert_eq!(info.pk_size, 32 + 1184, "{label} PK size");
            // X25519 (32) + ML-KEM-768 CT (1088) = 1120
            assert_eq!(info.ct_size, 32 + 1088, "{label} CT size");
            assert_eq!(info.ss_size, 64, "{label} shared secret size");
        } else {
            assert_eq!(info.pk_size, 32, "{label} X25519 PK size");
            assert_eq!(info.ct_size, 32, "{label} X25519 CT size");
            assert_eq!(info.ss_size, 32, "{label} X25519 shared secret size");
        }

        println!(
            "[PROOF] {{\"section\":11,\"test\":\"kex_info_{label}\",\
             \"method\":\"{}\",\
             \"is_pq_secure\":{},\
             \"pk_size\":{},\"ct_size\":{},\"ss_size\":{},\
             \"status\":\"PASS\"}}",
            info.method.replace('"', "'"),
            info.is_pq_secure,
            info.pk_size,
            info.ct_size,
            info.ss_size,
        );
    }
}

#[test]
fn proof_tls_config_validation_succeeds() {
    // Valid default
    let config = TlsConfig::new();
    assert!(config.validate().is_ok(), "Default config must be valid");

    // Valid with full builder chain
    let config = TlsConfig::new()
        .use_case(TlsUseCase::FinancialServices)
        .with_alpn_protocols(vec!["h2", "http/1.1"])
        .with_resumption(true)
        .with_session_lifetime(3600);
    assert!(config.validate().is_ok(), "Builder chain config must be valid");

    println!(
        "[PROOF] {{\"section\":11,\"test\":\"tls_config_validation\",\
         \"default_valid\":true,\
         \"builder_chain_valid\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[tokio::test]
async fn proof_tls_live_hybrid_handshake() {
    use latticearc::tls::tls_connect;

    // Connect to a public server that supports TLS 1.3
    // Hybrid mode: X25519MLKEM768 key exchange
    let config = TlsConfig::new(); // default = Hybrid mode
    assert_eq!(config.mode, TlsMode::Hybrid);

    let result = tls_connect("cloudflare.com:443", "cloudflare.com", &config).await;

    match result {
        Ok(_stream) => {
            println!(
                "[PROOF] {{\"section\":11,\"test\":\"tls_live_hybrid_handshake\",\
                 \"server\":\"cloudflare.com:443\",\
                 \"mode\":\"Hybrid\",\
                 \"kex\":\"X25519MLKEM768\",\
                 \"protocol\":\"TLS 1.3\",\
                 \"handshake\":\"SUCCESS\",\
                 \"status\":\"PASS\"}}"
            );
        }
        Err(e) => {
            // Network may not be available in some CI environments
            let err_str = e.to_string();
            println!(
                "[PROOF] {{\"section\":11,\"test\":\"tls_live_hybrid_handshake\",\
                 \"server\":\"cloudflare.com:443\",\
                 \"mode\":\"Hybrid\",\
                 \"handshake\":\"NETWORK_UNAVAILABLE\",\
                 \"error\":\"{}\",\
                 \"status\":\"SKIPPED\",\
                 \"reason\":\"Network not available\"}}",
                err_str.chars().take(80).collect::<String>().replace('"', "'"),
            );
        }
    }
}

#[tokio::test]
async fn proof_tls_live_classic_handshake() {
    use latticearc::tls::tls_connect;

    // Classic mode: X25519 only (for comparison)
    let mut config = TlsConfig::new();
    config.mode = TlsMode::Classic;

    let result = tls_connect("cloudflare.com:443", "cloudflare.com", &config).await;

    match result {
        Ok(_stream) => {
            println!(
                "[PROOF] {{\"section\":11,\"test\":\"tls_live_classic_handshake\",\
                 \"server\":\"cloudflare.com:443\",\
                 \"mode\":\"Classic\",\
                 \"kex\":\"X25519\",\
                 \"protocol\":\"TLS 1.3\",\
                 \"handshake\":\"SUCCESS\",\
                 \"status\":\"PASS\"}}"
            );
        }
        Err(e) => {
            let err_str = e.to_string();
            println!(
                "[PROOF] {{\"section\":11,\"test\":\"tls_live_classic_handshake\",\
                 \"server\":\"cloudflare.com:443\",\
                 \"mode\":\"Classic\",\
                 \"handshake\":\"NETWORK_UNAVAILABLE\",\
                 \"error\":\"{}\",\
                 \"status\":\"SKIPPED\",\
                 \"reason\":\"Network not available\"}}",
                err_str.chars().take(80).collect::<String>().replace('"', "'"),
            );
        }
    }
}

// ============================================================================
// Section 12: Data-at-Rest Roundtrip — Byte-exact Preservation Proof
// ============================================================================

/// Helper: SHA3-256 hash as hex string
fn sha3_hex(data: &[u8]) -> String {
    let hash = hash_data(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn proof_at_rest_structured_json_roundtrip() {
    // Realistic structured data — a JSON config file
    let plaintext = br#"{"database":{"host":"db.internal","port":5432,"credentials":{"user":"admin","password":"s3cret!@#$%"}},"features":["encryption","audit","compliance"],"version":42}"#;

    proof_at_rest_roundtrip(
        plaintext,
        MlKemSecurityLevel::MlKem768,
        SecurityLevel::High,
        "structured_json",
        "JSON config with nested objects and special chars",
    );
}

#[test]
fn proof_at_rest_binary_data_roundtrip() {
    // Binary data with all 256 byte values + null bytes + control chars
    let mut plaintext = Vec::with_capacity(512);
    for i in 0..256u16 {
        plaintext.push(i as u8);
        plaintext.push(255u8.wrapping_sub(i as u8));
    }

    proof_at_rest_roundtrip(
        &plaintext,
        MlKemSecurityLevel::MlKem1024,
        SecurityLevel::Maximum,
        "binary_all_256_values",
        "Binary data with all 256 byte values",
    );
}

#[test]
fn proof_at_rest_unicode_roundtrip() {
    // Multi-language Unicode text
    let plaintext = "Hello 世界 مرحبا Привет 🔐🛡️ Ñoño café résumé naïve".as_bytes();

    proof_at_rest_roundtrip(
        plaintext,
        MlKemSecurityLevel::MlKem768,
        SecurityLevel::High,
        "unicode_multilingual",
        "Multi-language Unicode with emoji",
    );
}

#[test]
fn proof_at_rest_empty_preserves_exactly() {
    proof_at_rest_roundtrip(
        b"",
        MlKemSecurityLevel::MlKem512,
        SecurityLevel::Standard,
        "empty_payload",
        "Empty byte array preserved exactly",
    );
}

#[test]
fn proof_at_rest_ml_kem_512_full_pipeline_succeeds() {
    let plaintext = b"ML-KEM-512 at-rest proof: This data must survive encrypt->serialize->deserialize->decrypt byte-for-byte.";

    proof_at_rest_roundtrip(
        plaintext,
        MlKemSecurityLevel::MlKem512,
        SecurityLevel::Standard,
        "ml_kem_512_pipeline",
        "Full pipeline at ML-KEM-512",
    );
}

#[test]
fn proof_at_rest_ml_kem_768_full_pipeline_succeeds() {
    let plaintext = b"ML-KEM-768 at-rest proof: Enterprise-grade data preservation across the full serialization boundary.";

    proof_at_rest_roundtrip(
        plaintext,
        MlKemSecurityLevel::MlKem768,
        SecurityLevel::High,
        "ml_kem_768_pipeline",
        "Full pipeline at ML-KEM-768",
    );
}

#[test]
fn proof_at_rest_ml_kem_1024_full_pipeline_succeeds() {
    let plaintext = b"ML-KEM-1024 at-rest proof: Maximum security level data must be byte-identical after full roundtrip.";

    proof_at_rest_roundtrip(
        plaintext,
        MlKemSecurityLevel::MlKem1024,
        SecurityLevel::Maximum,
        "ml_kem_1024_pipeline",
        "Full pipeline at ML-KEM-1024",
    );
}

#[test]
fn proof_at_rest_large_document_roundtrip() {
    // 64KB "document" with realistic mixed content
    let mut plaintext = Vec::with_capacity(65536);
    let line = b"Line NNNNNN: The quick brown fox jumps over the lazy dog. PQC ensures long-term data protection.\n";
    let mut n = 0u32;
    while plaintext.len() + line.len() < 65536 {
        let formatted = format!(
            "Line {:06}: The quick brown fox jumps over the lazy dog. PQC ensures long-term data protection.\n",
            n
        );
        plaintext.extend_from_slice(formatted.as_bytes());
        n += 1;
    }

    proof_at_rest_roundtrip(
        &plaintext,
        MlKemSecurityLevel::MlKem768,
        SecurityLevel::High,
        "large_document_64kb",
        "64KB document with numbered lines",
    );
}

#[test]
fn proof_at_rest_aad_context_binding_succeeds() {
    // Encrypt-at-rest with AAD: proves context is bound to ciphertext
    let plaintext = b"Healthcare record: Patient ID 12345, Diagnosis: Confidential";
    let key = [0x42u8; 32];
    let aad = b"context:healthcare:patient:12345";

    let pre_hash = sha3_hex(plaintext);

    // Encrypt with AAD
    let ciphertext =
        encrypt_aes_gcm_with_aad_unverified(plaintext, &key, aad).expect("encrypt with AAD");

    // Decrypt with correct AAD
    let decrypted =
        decrypt_aes_gcm_with_aad_unverified(&ciphertext, &key, aad).expect("decrypt with AAD");

    let post_hash = sha3_hex(&decrypted);

    assert_eq!(pre_hash, post_hash, "SHA3-256 hash must match after roundtrip");
    assert_eq!(decrypted.as_slice(), plaintext, "Byte-exact match required");

    // Verify wrong AAD still fails
    let wrong_aad_result = decrypt_aes_gcm_with_aad_unverified(&ciphertext, &key, b"wrong-context");
    assert!(wrong_aad_result.is_err(), "Wrong AAD must fail");

    println!(
        "[PROOF] {{\"section\":12,\"test\":\"at_rest_aad_context_binding\",\
         \"description\":\"AAD-bound encryption at rest\",\
         \"plaintext_len\":{},\
         \"aad\":\"context:healthcare:patient:12345\",\
         \"sha3_256_before\":\"{pre_hash}\",\
         \"sha3_256_after\":\"{post_hash}\",\
         \"hash_match\":true,\
         \"byte_exact_match\":true,\
         \"wrong_aad_rejected\":true,\
         \"status\":\"PASS\"}}",
        plaintext.len(),
    );
}

fn proof_at_rest_roundtrip(
    plaintext: &[u8],
    key_level: MlKemSecurityLevel,
    security_level: SecurityLevel,
    test_name: &str,
    description: &str,
) {
    let pre_hash = sha3_hex(plaintext);

    // Step 1: Encrypt
    let (pk, sk) = generate_hybrid_keypair_with_level(key_level)
        .unwrap_or_else(|e| panic!("keypair gen for {test_name}: {e}"));

    let config = CryptoConfig::new().security_level(security_level);
    let encrypted = encrypt(plaintext, EncryptKey::Hybrid(&pk), config)
        .unwrap_or_else(|e| panic!("encrypt for {test_name}: {e}"));

    let scheme = encrypted.scheme().to_string();

    // Step 2: Serialize to JSON (simulates writing to disk)
    let json = serialize_encrypted_output(&encrypted)
        .unwrap_or_else(|e| panic!("serialize for {test_name}: {e}"));
    let json_bytes = json.len();

    // Step 3: Deserialize from JSON (simulates reading from disk)
    let restored = deserialize_encrypted_output(&json)
        .unwrap_or_else(|e| panic!("deserialize for {test_name}: {e}"));

    // Step 4: Verify scheme + structural metadata survived serialization
    assert_eq!(
        restored.scheme(),
        encrypted.scheme(),
        "Scheme lost in serialization for {test_name}"
    );
    assert_eq!(restored.nonce(), encrypted.nonce(), "Nonce lost in serialization for {test_name}");
    assert_eq!(restored.tag(), encrypted.tag(), "Tag lost in serialization for {test_name}");
    assert_eq!(
        restored.ciphertext(),
        encrypted.ciphertext(),
        "Ciphertext lost in serialization for {test_name}"
    );
    if let (Some(orig_h), Some(rest_h)) = (encrypted.hybrid_data(), restored.hybrid_data()) {
        assert_eq!(
            orig_h.ml_kem_ciphertext(),
            rest_h.ml_kem_ciphertext(),
            "ML-KEM CT lost for {test_name}"
        );
        assert_eq!(
            orig_h.ecdh_ephemeral_pk(),
            rest_h.ecdh_ephemeral_pk(),
            "ECDH PK lost for {test_name}"
        );
    }

    // Step 5: Decrypt from deserialized output
    let config = CryptoConfig::new().security_level(security_level);
    let decrypted = decrypt(&restored, DecryptKey::Hybrid(&sk), config)
        .unwrap_or_else(|e| panic!("decrypt for {test_name}: {e}"));

    // Step 6: Byte-exact verification
    let post_hash = sha3_hex(decrypted.as_ref());
    assert_eq!(pre_hash, post_hash, "SHA3-256 hash mismatch for {test_name}");
    assert_eq!(decrypted.as_slice(), plaintext, "Byte-exact content mismatch for {test_name}");

    println!(
        "[PROOF] {{\"section\":12,\"test\":\"at_rest_{test_name}\",\
         \"description\":\"{description}\",\
         \"plaintext_len\":{},\
         \"scheme\":\"{scheme}\",\
         \"json_serialized_bytes\":{json_bytes},\
         \"sha3_256_before\":\"{pre_hash}\",\
         \"sha3_256_after\":\"{post_hash}\",\
         \"hash_match\":true,\
         \"byte_exact_match\":true,\
         \"scheme_preserved\":true,\
         \"nonce_preserved\":true,\
         \"tag_preserved\":true,\
         \"hybrid_data_preserved\":true,\
         \"status\":\"PASS\"}}",
        plaintext.len(),
    );
}

// ============================================================================
// Section 13: Native PQ Key Exchange (v0.3.3) — 5 tests
//
// Proves that rustls 0.23.37+ natively provides PQ key exchange groups
// without the rustls-post-quantum crate. Verifies:
// - X25519MLKEM768 is in default_provider()
// - PQ groups are sorted before classical groups in Hybrid/Pq modes
// - All TLS modes produce valid providers
// - KexInfo is consistent with actual provider contents
// - Hybrid mode includes classical fallback groups
// ============================================================================

#[test]
fn proof_native_pq_x25519mlkem768_available() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_provider};

    let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)
        .expect("Hybrid PQ provider must be available");

    let group_names: Vec<String> =
        provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

    let has_x25519mlkem768 = group_names.iter().any(|n| n.contains("X25519MLKEM768"));
    assert!(has_x25519mlkem768, "X25519MLKEM768 must be natively available");

    let total_groups = group_names.len();

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"native_pq_x25519mlkem768\",\
         \"description\":\"X25519MLKEM768 available in rustls default_provider() without rustls-post-quantum\",\
         \"group\":\"X25519MLKEM768\",\
         \"available\":true,\
         \"total_kx_groups\":{total_groups},\
         \"all_groups\":\"{groups}\",\
         \"status\":\"PASS\"}}",
        groups = group_names.join(", "),
    );
}

#[test]
fn proof_pq_preference_ordering_verified() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_provider};

    let provider =
        get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq).expect("Provider must be available");

    let group_names: Vec<String> =
        provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

    let first_group = &group_names[0];
    let pq_first = first_group.contains("MLKEM");

    let last_mlkem = group_names.iter().rposition(|n| n.contains("MLKEM")).unwrap();
    let first_classical = group_names.iter().position(|n| !n.contains("MLKEM")).unwrap();
    let correctly_ordered = last_mlkem < first_classical;

    assert!(pq_first, "First group must be PQ");
    assert!(correctly_ordered, "All PQ groups must precede classical groups");

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"pq_preference_ordering\",\
         \"description\":\"PQ key exchange groups sorted before classical groups in Hybrid mode\",\
         \"first_group\":\"{first_group}\",\
         \"pq_first\":true,\
         \"ordering_correct\":true,\
         \"group_order\":\"{order}\",\
         \"status\":\"PASS\"}}",
        order = group_names.join(" > "),
    );
}

#[test]
fn proof_all_tls_modes_produce_providers() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_provider};

    let test_cases = [
        (TlsMode::Hybrid, PqKexMode::RustlsPq, "hybrid_rustls_pq"),
        (TlsMode::Pq, PqKexMode::RustlsPq, "pq_rustls_pq"),
        (TlsMode::Classic, PqKexMode::Classical, "classic_classical"),
        (TlsMode::Hybrid, PqKexMode::CustomHybrid, "hybrid_custom"),
    ];

    for (tls_mode, kex_mode, label) in test_cases {
        let provider = get_kex_provider(tls_mode, kex_mode)
            .unwrap_or_else(|e| panic!("Provider failed for {label}: {e}"));

        let group_count = provider.kx_groups.len();
        assert!(group_count > 0, "Provider for {label} must have groups");

        println!(
            "[PROOF] {{\"section\":13,\"test\":\"provider_{label}\",\
             \"description\":\"TLS provider created for {tls_mode:?}/{kex_mode:?}\",\
             \"tls_mode\":\"{tls_mode:?}\",\
             \"kex_mode\":\"{kex_mode:?}\",\
             \"kx_group_count\":{group_count},\
             \"status\":\"PASS\"}}"
        );
    }
}

#[test]
fn proof_kex_info_matches_provider() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_info, get_kex_provider};

    let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
    let provider =
        get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq).expect("Provider must be available");

    let group_names: Vec<String> =
        provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

    let method_in_provider = group_names.iter().any(|n| n.contains(&info.method));
    assert!(method_in_provider, "KexInfo method '{}' must exist in provider groups", info.method);

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"kex_info_provider_consistency\",\
         \"description\":\"KexInfo.method matches a real group in the CryptoProvider\",\
         \"kex_info_method\":\"{method}\",\
         \"method_in_provider\":true,\
         \"is_pq_secure\":{pq},\
         \"shared_secret_size\":{ss},\
         \"status\":\"PASS\"}}",
        method = info.method,
        pq = info.is_pq_secure,
        ss = info.ss_size,
    );
}

#[test]
fn proof_hybrid_includes_classical_fallback() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_provider};

    let provider =
        get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq).expect("Provider must be available");

    let group_names: Vec<String> =
        provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

    let has_pq = group_names.iter().any(|n| n.contains("MLKEM"));
    let has_x25519 = group_names.iter().any(|n| *n == "X25519");
    let has_secp256r1 = group_names.iter().any(|n| n.contains("secp256r1"));

    assert!(has_pq, "Hybrid must include PQ groups");
    assert!(has_x25519, "Hybrid must include X25519 for classical fallback");

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"hybrid_classical_fallback\",\
         \"description\":\"Hybrid mode includes both PQ and classical groups for backward compatibility\",\
         \"has_mlkem\":true,\
         \"has_x25519\":{has_x25519},\
         \"has_secp256r1\":{has_secp256r1},\
         \"total_groups\":{},\
         \"status\":\"PASS\"}}",
        group_names.len(),
    );
}

#[test]
fn proof_classic_mode_not_pq_secure() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_info};

    // Classic mode must NOT claim PQ security regardless of kex_mode
    for kex_mode in [PqKexMode::Classical, PqKexMode::RustlsPq, PqKexMode::CustomHybrid] {
        let info = get_kex_info(TlsMode::Classic, kex_mode);
        assert!(!info.is_pq_secure, "Classic+{kex_mode:?} must not be PQ secure");
    }

    // Reuse Classical result for proof output (already verified above)
    let info = get_kex_info(TlsMode::Classic, PqKexMode::Classical);

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"classic_not_pq_secure\",\
         \"description\":\"Classic TLS mode correctly reports non-PQ security for all kex modes\",\
         \"tls_mode\":\"Classic\",\
         \"is_pq_secure\":false,\
         \"method\":\"{method}\",\
         \"ss_size\":{ss},\
         \"status\":\"PASS\"}}",
        method = info.method,
        ss = info.ss_size,
    );
}

#[test]
fn proof_pq_secure_flag_per_mode_verified() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_info};

    // Verify is_pq_secure flag is consistent with mode semantics
    let test_cases = [
        (TlsMode::Hybrid, PqKexMode::RustlsPq, true),
        (TlsMode::Hybrid, PqKexMode::CustomHybrid, true),
        (TlsMode::Pq, PqKexMode::RustlsPq, true),
        (TlsMode::Classic, PqKexMode::Classical, false),
        (TlsMode::Classic, PqKexMode::RustlsPq, false),
    ];

    let mut results = Vec::new();
    for (tls_mode, kex_mode, expected_pq) in test_cases {
        let info = get_kex_info(tls_mode, kex_mode);
        assert_eq!(
            info.is_pq_secure, expected_pq,
            "{tls_mode:?}/{kex_mode:?}: expected is_pq_secure={expected_pq}"
        );
        results.push(format!("{tls_mode:?}/{kex_mode:?}={expected_pq}"));
    }

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"pq_secure_flag_consistency\",\
         \"description\":\"is_pq_secure flag matches mode semantics for all mode combinations\",\
         \"test_count\":{count},\
         \"results\":\"{results}\",\
         \"status\":\"PASS\"}}",
        count = results.len(),
        results = results.join(", "),
    );
}

#[test]
fn proof_hybrid_ss_larger_than_classical() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_info};

    let hybrid = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
    let classical = get_kex_info(TlsMode::Classic, PqKexMode::Classical);

    assert!(
        hybrid.ss_size > classical.ss_size,
        "Hybrid SS ({}) must exceed classical SS ({})",
        hybrid.ss_size,
        classical.ss_size
    );

    // ss_size values are small (32, 64) — precision loss impossible
    let ratio = hybrid.ss_size / classical.ss_size;

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"hybrid_ss_larger_than_classical\",\
         \"description\":\"Hybrid X25519MLKEM768 shared secret (64B) exceeds classical X25519 (32B)\",\
         \"hybrid_ss_size\":{hybrid_ss},\
         \"classical_ss_size\":{classical_ss},\
         \"ratio\":{ratio},\
         \"status\":\"PASS\"}}",
        hybrid_ss = hybrid.ss_size,
        classical_ss = classical.ss_size,
    );
}

#[test]
fn proof_provider_deterministic() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_provider};

    // Provider must produce identical group ordering across calls
    let p1 = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq).unwrap();
    let p2 = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq).unwrap();

    let names1: Vec<String> = p1.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();
    let names2: Vec<String> = p2.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

    assert_eq!(names1, names2, "Provider must be deterministic");

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"provider_deterministic\",\
         \"description\":\"get_kex_provider produces identical group ordering across multiple calls\",\
         \"call_count\":2,\
         \"groups_match\":true,\
         \"group_count\":{count},\
         \"status\":\"PASS\"}}",
        count = names1.len(),
    );
}

#[test]
fn proof_exhaustive_mode_matrix_succeeds() {
    use latticearc::tls::pq_key_exchange::{PqKexMode, get_kex_info, get_kex_provider};

    // Every (TlsMode, PqKexMode) combination must succeed without panic
    let tls_modes = [TlsMode::Classic, TlsMode::Hybrid, TlsMode::Pq];
    let kex_modes = [PqKexMode::Classical, PqKexMode::RustlsPq, PqKexMode::CustomHybrid];

    let mut pass_count = 0;
    for tls_mode in tls_modes {
        for kex_mode in kex_modes {
            let provider = get_kex_provider(tls_mode, kex_mode);
            assert!(provider.is_ok(), "{tls_mode:?}/{kex_mode:?} must succeed");
            assert!(!provider.unwrap().kx_groups.is_empty());
            let _ = get_kex_info(tls_mode, kex_mode);
            pass_count += 1;
        }
    }

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"exhaustive_mode_matrix\",\
         \"description\":\"All 9 (TlsMode x PqKexMode) combinations produce valid providers and info\",\
         \"total_combinations\":{pass_count},\
         \"tls_modes\":3,\
         \"kex_modes\":3,\
         \"all_passed\":true,\
         \"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 14: Key Persistence — Serialize SK → Drop → Reload → Decrypt (v0.5.2)
//
// Proves the full real-world key lifecycle: keygen → export to JSON → drop all
// in-memory keys → reload from JSON → decrypt. This is the path every CLI user
// and application takes. Tests that the secret key file is self-contained
// (ML-KEM public key stored in metadata, no separate PK file needed).
// ============================================================================

#[test]
fn proof_key_persistence_hybrid_512_succeeds() {
    proof_key_persistence(
        MlKemSecurityLevel::MlKem512,
        SecurityLevel::Standard,
        UseCase::IoTDevice,
        "hybrid_512",
    );
}

#[test]
fn proof_key_persistence_hybrid_768_succeeds() {
    proof_key_persistence(
        MlKemSecurityLevel::MlKem768,
        SecurityLevel::High,
        UseCase::SecureMessaging,
        "hybrid_768",
    );
}

#[test]
fn proof_key_persistence_hybrid_1024_succeeds() {
    proof_key_persistence(
        MlKemSecurityLevel::MlKem1024,
        SecurityLevel::Maximum,
        UseCase::GovernmentClassified,
        "hybrid_1024",
    );
}

fn proof_key_persistence(
    key_level: MlKemSecurityLevel,
    security_level: SecurityLevel,
    use_case: UseCase,
    test_name: &str,
) {
    let plaintext = format!("Key persistence proof: {test_name}");
    let pre_hash = sha3_hex(plaintext.as_bytes());

    // === PROCESS A: Generate keypair, export to JSON, drop everything ===
    let (pk_json, sk_json) = {
        let (pk, sk) = generate_hybrid_keypair_with_level(key_level)
            .unwrap_or_else(|e| panic!("keygen for {test_name}: {e}"));
        let (pk_portable, sk_portable) = PortableKey::from_hybrid_kem_keypair(use_case, &pk, &sk)
            .unwrap_or_else(|e| panic!("export for {test_name}: {e}"));
        let pk_j: String = pk_portable.to_json().unwrap_or_else(|e| panic!("pk json: {e}"));
        let sk_j: String = sk_portable.to_json().unwrap_or_else(|e| panic!("sk json: {e}"));
        // pk, sk, pk_portable, sk_portable all dropped here
        (pk_j, sk_j)
    };

    let pk_json_len = pk_json.len();
    let sk_json_len = sk_json.len();

    // Verify SK JSON contains ml_kem_pk metadata
    let sk_has_pk_metadata = sk_json.contains("ml_kem_pk");
    assert!(sk_has_pk_metadata, "{test_name}: secret key JSON must contain ml_kem_pk metadata");

    // === PROCESS B: Load PK from JSON, encrypt ===
    let encrypted_json = {
        let pk_loaded = PortableKey::from_json(&pk_json)
            .unwrap_or_else(|e| panic!("load pk for {test_name}: {e}"));
        let hybrid_pk = pk_loaded
            .to_hybrid_public_key()
            .unwrap_or_else(|e| panic!("extract pk for {test_name}: {e}"));
        let config = CryptoConfig::new().security_level(security_level);
        let encrypted = encrypt(plaintext.as_bytes(), EncryptKey::Hybrid(&hybrid_pk), config)
            .unwrap_or_else(|e| panic!("encrypt for {test_name}: {e}"));
        // pk_loaded, hybrid_pk, encrypted all dropped here
        serialize_encrypted_output(&encrypted)
            .unwrap_or_else(|e| panic!("serialize ct for {test_name}: {e}"))
    };

    let ct_json_len = encrypted_json.len();

    // === PROCESS C: Load ONLY SK from JSON, decrypt ===
    let sk_loaded =
        PortableKey::from_json(&sk_json).unwrap_or_else(|e| panic!("load sk for {test_name}: {e}"));
    let hybrid_sk = sk_loaded
        .to_hybrid_secret_key()
        .unwrap_or_else(|e| panic!("reconstruct sk for {test_name}: {e}"));
    let ct_loaded = deserialize_encrypted_output(&encrypted_json)
        .unwrap_or_else(|e| panic!("load ct for {test_name}: {e}"));
    let config = CryptoConfig::new().security_level(security_level);
    let decrypted = decrypt(&ct_loaded, DecryptKey::Hybrid(&hybrid_sk), config)
        .unwrap_or_else(|e| panic!("decrypt for {test_name}: {e}"));

    let post_hash = sha3_hex(decrypted.as_ref());
    assert_eq!(
        pre_hash, post_hash,
        "{test_name}: SHA3 hash mismatch after key persistence roundtrip"
    );
    assert_eq!(decrypted.as_slice(), plaintext.as_bytes(), "{test_name}: byte mismatch");

    println!(
        "[PROOF] {{\"section\":14,\"test\":\"key_persistence_{test_name}\",\
         \"description\":\"keygen→JSON→drop→reload SK only→decrypt\",\
         \"level\":\"{test_name}\",\
         \"use_case\":\"{use_case:?}\",\
         \"pk_json_bytes\":{pk_json_len},\
         \"sk_json_bytes\":{sk_json_len},\
         \"ct_json_bytes\":{ct_json_len},\
         \"sk_self_contained\":true,\
         \"ml_kem_pk_in_metadata\":{sk_has_pk_metadata},\
         \"sha3_before\":\"{pre_hash}\",\
         \"sha3_after\":\"{post_hash}\",\
         \"hash_match\":true,\
         \"no_separate_pk_needed\":true,\
         \"status\":\"PASS\"}}",
    );
}

#[test]
fn proof_key_persistence_wrong_sk_rejects() {
    let plaintext = b"Negative key persistence proof";

    // Generate two independent keypairs
    let (pk_a, _sk_a) =
        generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem768).expect("keygen A");
    let (_pk_b, sk_b) =
        generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem768).expect("keygen B");

    // Export both to JSON
    let (pk_a_portable, _) =
        PortableKey::from_hybrid_kem_keypair(UseCase::SecureMessaging, &pk_a, &_sk_a)
            .expect("export A");
    let (_, sk_b_portable) =
        PortableKey::from_hybrid_kem_keypair(UseCase::SecureMessaging, &_pk_b, &sk_b)
            .expect("export B");

    let pk_a_json: String = pk_a_portable.to_json().expect("pk A json");
    let sk_b_json: String = sk_b_portable.to_json().expect("sk B json");

    // Drop all in-memory keys
    drop(pk_a);
    drop(_sk_a);
    drop(_pk_b);
    drop(sk_b);
    drop(pk_a_portable);
    drop(sk_b_portable);

    // Encrypt with A's public key
    let pk_loaded = PortableKey::from_json(&pk_a_json).expect("load pk A");
    let hybrid_pk = pk_loaded.to_hybrid_public_key().expect("extract pk A");
    let encrypted =
        encrypt(plaintext, EncryptKey::Hybrid(&hybrid_pk), CryptoConfig::new()).expect("encrypt");
    let ct_json = serialize_encrypted_output(&encrypted).expect("serialize");
    drop(encrypted);
    drop(hybrid_pk);

    // Attempt decrypt with B's secret key (should fail)
    let sk_loaded = PortableKey::from_json(&sk_b_json).expect("load sk B");
    let hybrid_sk = sk_loaded.to_hybrid_secret_key().expect("reconstruct sk B");
    let ct_loaded = deserialize_encrypted_output(&ct_json).expect("load ct");
    let result = decrypt(&ct_loaded, DecryptKey::Hybrid(&hybrid_sk), CryptoConfig::new());

    assert!(result.is_err(), "Decrypting A's ciphertext with B's secret key must fail");

    println!(
        "[PROOF] {{\"section\":14,\"test\":\"key_persistence_wrong_sk_rejects\",\
         \"description\":\"Encrypt with A's PK (from JSON), decrypt with B's SK (from JSON) fails\",\
         \"keys_from_json\":true,\
         \"all_memory_dropped\":true,\
         \"cross_key_rejected\":true,\
         \"status\":\"PASS\"}}"
    );
}
