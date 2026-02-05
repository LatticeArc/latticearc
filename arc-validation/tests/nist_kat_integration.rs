#![deny(unsafe_code)]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

//! NIST Known Answer Test Integration Suite
//!
//! This test file runs all NIST and RFC test vectors to validate
//! cryptographic implementations for FIPS compliance.

use arc_validation::nist_kat::*;

#[test]
fn test_all_nist_kat() {
    println!("\n========================================");
    println!("Running NIST Known Answer Tests");
    println!("========================================\n");

    let mut runner = KatRunner::new();

    // ML-KEM Tests
    println!("Testing ML-KEM...");
    runner.run_test("ML-KEM-512", "ML-KEM", || ml_kem_kat::run_ml_kem_512_kat());
    runner.run_test("ML-KEM-768", "ML-KEM", || ml_kem_kat::run_ml_kem_768_kat());
    runner.run_test("ML-KEM-1024", "ML-KEM", || ml_kem_kat::run_ml_kem_1024_kat());

    // ML-DSA Tests
    println!("Testing ML-DSA...");
    runner.run_test("ML-DSA-44", "ML-DSA", || ml_dsa_kat::run_ml_dsa_44_kat());
    runner.run_test("ML-DSA-65", "ML-DSA", || ml_dsa_kat::run_ml_dsa_65_kat());
    runner.run_test("ML-DSA-87", "ML-DSA", || ml_dsa_kat::run_ml_dsa_87_kat());

    // AES-GCM Tests
    println!("Testing AES-GCM...");
    runner.run_test("AES-128-GCM", "AES-GCM", || aes_gcm_kat::run_aes_128_gcm_kat());
    runner.run_test("AES-256-GCM", "AES-GCM", || aes_gcm_kat::run_aes_256_gcm_kat());

    // SHA-2 Tests
    println!("Testing SHA-2 Family...");
    runner.run_test("SHA-224", "SHA-2", || sha2_kat::run_sha224_kat());
    runner.run_test("SHA-256", "SHA-2", || sha2_kat::run_sha256_kat());
    runner.run_test("SHA-384", "SHA-2", || sha2_kat::run_sha384_kat());
    runner.run_test("SHA-512", "SHA-2", || sha2_kat::run_sha512_kat());
    runner.run_test("SHA-512/224", "SHA-2", || sha2_kat::run_sha512_224_kat());
    runner.run_test("SHA-512/256", "SHA-2", || sha2_kat::run_sha512_256_kat());

    // HKDF Tests
    println!("Testing HKDF...");
    runner.run_test("HKDF-SHA256", "HKDF", || hkdf_kat::run_hkdf_sha256_kat());

    // HMAC Tests
    println!("Testing HMAC...");
    runner.run_test("HMAC-SHA224", "HMAC", || hmac_kat::run_hmac_sha224_kat());
    runner.run_test("HMAC-SHA256", "HMAC", || hmac_kat::run_hmac_sha256_kat());
    runner.run_test("HMAC-SHA384", "HMAC", || hmac_kat::run_hmac_sha384_kat());
    runner.run_test("HMAC-SHA512", "HMAC", || hmac_kat::run_hmac_sha512_kat());

    // ChaCha20-Poly1305 Tests
    println!("Testing ChaCha20-Poly1305...");
    runner.run_test("ChaCha20-Poly1305", "AEAD", || {
        chacha20_poly1305_kat::run_chacha20_poly1305_kat()
    });

    // Get summary and print
    let summary = runner.finish();
    summary.print();

    // Assert all tests passed
    assert!(
        summary.all_passed(),
        "NIST KAT failures detected: {}/{} tests failed",
        summary.failed,
        summary.total
    );
}

#[test]
fn test_ml_kem_only() {
    println!("\nTesting ML-KEM algorithms only...");
    let mut runner = KatRunner::new();

    runner.run_test("ML-KEM-512", "ML-KEM", || ml_kem_kat::run_ml_kem_512_kat());
    runner.run_test("ML-KEM-768", "ML-KEM", || ml_kem_kat::run_ml_kem_768_kat());
    runner.run_test("ML-KEM-1024", "ML-KEM", || ml_kem_kat::run_ml_kem_1024_kat());

    let summary = runner.finish();
    summary.print();
    assert!(summary.all_passed());
}

#[test]
fn test_symmetric_crypto_only() {
    println!("\nTesting symmetric cryptography only...");
    let mut runner = KatRunner::new();

    runner.run_test("AES-128-GCM", "AES-GCM", || aes_gcm_kat::run_aes_128_gcm_kat());
    runner.run_test("AES-256-GCM", "AES-GCM", || aes_gcm_kat::run_aes_256_gcm_kat());
    runner.run_test("ChaCha20-Poly1305", "AEAD", || {
        chacha20_poly1305_kat::run_chacha20_poly1305_kat()
    });

    let summary = runner.finish();
    summary.print();
    assert!(summary.all_passed());
}

#[test]
fn test_hash_functions_only() {
    println!("\nTesting hash functions only...");
    let mut runner = KatRunner::new();

    runner.run_test("SHA-224", "SHA-2", || sha2_kat::run_sha224_kat());
    runner.run_test("SHA-256", "SHA-2", || sha2_kat::run_sha256_kat());
    runner.run_test("SHA-384", "SHA-2", || sha2_kat::run_sha384_kat());
    runner.run_test("SHA-512", "SHA-2", || sha2_kat::run_sha512_kat());
    runner.run_test("SHA-512/224", "SHA-2", || sha2_kat::run_sha512_224_kat());
    runner.run_test("SHA-512/256", "SHA-2", || sha2_kat::run_sha512_256_kat());

    let summary = runner.finish();
    summary.print();
    assert!(summary.all_passed());
}

#[test]
fn test_kdf_functions_only() {
    println!("\nTesting key derivation functions only...");
    let mut runner = KatRunner::new();

    runner.run_test("HKDF-SHA256", "HKDF", || hkdf_kat::run_hkdf_sha256_kat());
    runner.run_test("HMAC-SHA224", "HMAC", || hmac_kat::run_hmac_sha224_kat());
    runner.run_test("HMAC-SHA256", "HMAC", || hmac_kat::run_hmac_sha256_kat());
    runner.run_test("HMAC-SHA384", "HMAC", || hmac_kat::run_hmac_sha384_kat());
    runner.run_test("HMAC-SHA512", "HMAC", || hmac_kat::run_hmac_sha512_kat());

    let summary = runner.finish();
    summary.print();
    assert!(summary.all_passed());
}

#[test]
fn test_vector_count() {
    // Verify we have adequate test coverage
    println!("\nVerifying test vector counts...");

    let ml_kem_512_count = ml_kem_kat::ML_KEM_512_VECTORS.len();
    let ml_kem_768_count = ml_kem_kat::ML_KEM_768_VECTORS.len();
    let ml_kem_1024_count = ml_kem_kat::ML_KEM_1024_VECTORS.len();

    let ml_dsa_44_count = ml_dsa_kat::ML_DSA_44_VECTORS.len();
    let ml_dsa_65_count = ml_dsa_kat::ML_DSA_65_VECTORS.len();
    let ml_dsa_87_count = ml_dsa_kat::ML_DSA_87_VECTORS.len();

    let aes_128_gcm_count = aes_gcm_kat::AES_128_GCM_VECTORS.len();
    let aes_256_gcm_count = aes_gcm_kat::AES_256_GCM_VECTORS.len();

    let sha256_count = sha2_kat::SHA256_VECTORS.len();
    let sha224_count = sha2_kat::SHA224_VECTORS.len();
    let sha384_count = sha2_kat::SHA384_VECTORS.len();
    let sha512_count = sha2_kat::SHA512_VECTORS.len();

    let hkdf_count = hkdf_kat::HKDF_SHA256_VECTORS.len();
    let hmac_count = hmac_kat::HMAC_VECTORS.len();
    let chacha_count = chacha20_poly1305_kat::CHACHA20_POLY1305_VECTORS.len();

    let total_vectors = ml_kem_512_count
        + ml_kem_768_count
        + ml_kem_1024_count
        + ml_dsa_44_count
        + ml_dsa_65_count
        + ml_dsa_87_count
        + aes_128_gcm_count
        + aes_256_gcm_count
        + sha256_count
        + sha224_count
        + sha384_count
        + sha512_count
        + hkdf_count
        + (hmac_count * 4) // 4 HMAC variants
        + chacha_count;

    println!("\nTest Vector Summary:");
    println!("  ML-KEM-512:          {}", ml_kem_512_count);
    println!("  ML-KEM-768:          {}", ml_kem_768_count);
    println!("  ML-KEM-1024:         {}", ml_kem_1024_count);
    println!("  ML-DSA-44:           {}", ml_dsa_44_count);
    println!("  ML-DSA-65:           {}", ml_dsa_65_count);
    println!("  ML-DSA-87:           {}", ml_dsa_87_count);
    println!("  AES-128-GCM:         {}", aes_128_gcm_count);
    println!("  AES-256-GCM:         {}", aes_256_gcm_count);
    println!("  SHA-256:             {}", sha256_count);
    println!("  SHA-224:             {}", sha224_count);
    println!("  SHA-384:             {}", sha384_count);
    println!("  SHA-512:             {}", sha512_count);
    println!("  HKDF-SHA256:         {}", hkdf_count);
    println!("  HMAC (all variants): {}", hmac_count * 4);
    println!("  ChaCha20-Poly1305:   {}", chacha_count);
    println!("  ----------------------------------------");
    println!("  TOTAL VECTORS:       {}", total_vectors);

    // Verify we meet the 50+ test vector requirement
    assert!(total_vectors >= 50, "Insufficient test vectors: {} < 50", total_vectors);

    println!("\n✓ Test vector count requirement met: {} >= 50", total_vectors);
}
