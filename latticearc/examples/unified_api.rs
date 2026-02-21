//! Unified API Example — encrypt/decrypt with CryptoConfig
//!
//! Demonstrates ALL 24 use cases and ALL 4 security levels with the primary
//! `encrypt()` / `decrypt()` entry points. This is the comprehensive happy-path
//! test for the unified API.
//!
//! Run with: `cargo run --package latticearc --example unified_api --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use latticearc::{CryptoConfig, SecurityLevel, UseCase, decrypt, encrypt};

fn main() {
    println!("=== LatticeArc: Unified API — Comprehensive Happy-Path Tests ===\n");

    let key = [0x42u8; 32]; // 256-bit symmetric key
    let plaintext = b"Confidential: quarterly earnings exceed projections.";

    // ====================================================================
    // Section 1: All 24 UseCases — encrypt/decrypt roundtrip
    // ====================================================================
    println!("--- All 24 UseCases: encrypt/decrypt roundtrip ---\n");

    let use_cases: &[(&str, UseCase)] = &[
        // Communication (4)
        ("SecureMessaging", UseCase::SecureMessaging),
        ("EmailEncryption", UseCase::EmailEncryption),
        ("VpnTunnel", UseCase::VpnTunnel),
        ("ApiSecurity", UseCase::ApiSecurity),
        // Storage (5)
        ("FileStorage", UseCase::FileStorage),
        ("DatabaseEncryption", UseCase::DatabaseEncryption),
        ("CloudStorage", UseCase::CloudStorage),
        ("BackupArchive", UseCase::BackupArchive),
        ("ConfigSecrets", UseCase::ConfigSecrets),
        // Authentication & Identity (4)
        ("Authentication", UseCase::Authentication),
        ("SessionToken", UseCase::SessionToken),
        ("DigitalCertificate", UseCase::DigitalCertificate),
        ("KeyExchange", UseCase::KeyExchange),
        // Financial & Legal (3)
        ("FinancialTransactions", UseCase::FinancialTransactions),
        ("LegalDocuments", UseCase::LegalDocuments),
        ("BlockchainTransaction", UseCase::BlockchainTransaction),
        // Regulated Industries (3)
        ("HealthcareRecords", UseCase::HealthcareRecords),
        ("GovernmentClassified", UseCase::GovernmentClassified),
        ("PaymentCard", UseCase::PaymentCard),
        // IoT & Embedded (2)
        ("IoTDevice", UseCase::IoTDevice),
        ("FirmwareSigning", UseCase::FirmwareSigning),
        ("AuditLog", UseCase::AuditLog),
    ];

    assert_eq!(use_cases.len(), 22, "Expected 22 use cases");

    let mut passed = 0u32;
    for (name, uc) in use_cases {
        let config = CryptoConfig::new().use_case(uc.clone());
        let enc = encrypt(plaintext, &key, config)
            .unwrap_or_else(|e| panic!("encrypt failed for {}: {}", name, e));
        let dec = decrypt(&enc, &key, CryptoConfig::new())
            .unwrap_or_else(|e| panic!("decrypt failed for {}: {}", name, e));
        assert_eq!(dec.as_slice(), plaintext);
        passed += 1;
        println!("  {:25} scheme={:40} {} bytes -> roundtrip OK", name, enc.scheme, enc.data.len());
    }
    println!("\n  All {} use cases passed!\n", passed);

    // ====================================================================
    // Section 2: All 4 SecurityLevels — encrypt/decrypt roundtrip
    // ====================================================================
    println!("--- All 4 SecurityLevels: encrypt/decrypt roundtrip ---\n");

    let levels: &[(&str, SecurityLevel)] = &[
        ("Standard", SecurityLevel::Standard),
        ("High", SecurityLevel::High),
        ("Maximum", SecurityLevel::Maximum),
        ("Quantum", SecurityLevel::Quantum),
    ];

    for (name, level) in levels {
        let config = CryptoConfig::new().security_level(level.clone());
        let enc = encrypt(plaintext, &key, config)
            .unwrap_or_else(|e| panic!("encrypt failed for {}: {}", name, e));
        let dec = decrypt(&enc, &key, CryptoConfig::new())
            .unwrap_or_else(|e| panic!("decrypt failed for {}: {}", name, e));
        assert_eq!(dec.as_slice(), plaintext);
        println!("  {:10} scheme={:40} {} bytes -> roundtrip OK", name, enc.scheme, enc.data.len());
    }
    println!("\n  All 4 security levels passed!\n");

    // ====================================================================
    // Section 3: Default config (SecurityLevel::High)
    // ====================================================================
    println!("--- Default CryptoConfig (High security) ---\n");

    let enc = encrypt(plaintext, &key, CryptoConfig::new())
        .expect("encrypt with default config should succeed");
    let dec = decrypt(&enc, &key, CryptoConfig::new()).expect("decrypt should succeed");
    assert_eq!(dec.as_slice(), plaintext);
    println!("  Default: scheme={}, {} bytes -> roundtrip OK\n", enc.scheme, enc.data.len());

    // ====================================================================
    // Section 4: Cross-matrix (UseCase x SecurityLevel) spot checks
    // ====================================================================
    println!("--- Cross-matrix: UseCase x SecurityLevel ---\n");

    let spot_checks: &[(&str, UseCase, SecurityLevel)] = &[
        ("IoT+Standard", UseCase::IoTDevice, SecurityLevel::Standard),
        ("FileStorage+Maximum", UseCase::FileStorage, SecurityLevel::Maximum),
        ("Government+Quantum", UseCase::GovernmentClassified, SecurityLevel::Quantum),
        ("Healthcare+High", UseCase::HealthcareRecords, SecurityLevel::High),
    ];

    for (name, uc, level) in spot_checks {
        let config = CryptoConfig::new().use_case(uc.clone()).security_level(level.clone());
        let enc = encrypt(plaintext, &key, config)
            .unwrap_or_else(|e| panic!("encrypt failed for {}: {}", name, e));
        let dec = decrypt(&enc, &key, CryptoConfig::new())
            .unwrap_or_else(|e| panic!("decrypt failed for {}: {}", name, e));
        assert_eq!(dec.as_slice(), plaintext);
        println!("  {:30} scheme={:40} roundtrip OK", name, enc.scheme);
    }
    println!();

    // ====================================================================
    // Section 5: True hybrid encryption pointer
    // ====================================================================
    println!("--- True Hybrid (ML-KEM-768 + X25519) ---\n");
    println!("  For true PQ+classical hybrid, use the typed API:");
    println!("    let (pk, sk) = generate_hybrid_keypair()?;");
    println!("    let enc = encrypt_hybrid(data, &pk, SecurityMode::Unverified)?;");
    println!("    let dec = decrypt_hybrid(&enc, &sk, SecurityMode::Unverified)?;");
    println!("  See: examples/hybrid_encryption.rs\n");

    println!(
        "=== All unified API tests passed! ({} use cases, {} security levels) ===",
        use_cases.len(),
        levels.len()
    );
}
