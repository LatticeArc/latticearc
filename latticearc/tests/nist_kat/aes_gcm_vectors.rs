//! AES-GCM Known Answer Tests (NIST SP 800-38D)
//!
//! Test vectors derived from NIST SP 800-38D and official CAVP test files.
//! These tests validate the AES-GCM implementation against official NIST values.

#![allow(clippy::expect_used)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::indexing_slicing)]

use super::common::{constant_time_eq, decode_hex};
use arc_primitives::aead::AeadCipher;
use arc_primitives::aead::aes_gcm::{AesGcm128, AesGcm256};

/// NIST SP 800-38D AES-128-GCM Test Vector 1
/// Test Case 1 from gcmEncryptExtIV128.rsp
const AES_128_KEY_1: &str = "00000000000000000000000000000000";
const AES_128_IV_1: &str = "000000000000000000000000";
const AES_128_PT_1: &str = "";
const AES_128_AAD_1: &str = "";
const AES_128_CT_1: &str = "";
const AES_128_TAG_1: &str = "58e2fccefa7e3061367f1d57a4e7455a";

/// NIST SP 800-38D AES-128-GCM Test Vector 2
/// Test Case 2 with plaintext
const AES_128_KEY_2: &str = "00000000000000000000000000000000";
const AES_128_IV_2: &str = "000000000000000000000000";
const AES_128_PT_2: &str = "00000000000000000000000000000000";
const AES_128_AAD_2: &str = "";
const AES_128_CT_2: &str = "0388dace60b6a392f328c2b971b2fe78";
const AES_128_TAG_2: &str = "ab6e47d42cec13bdf53a67b21257bddf";

/// NIST SP 800-38D AES-128-GCM Test Vector 3
/// Test Case 3 with AAD
const AES_128_KEY_3: &str = "feffe9928665731c6d6a8f9467308308";
const AES_128_IV_3: &str = "cafebabefacedbaddecaf888";
const AES_128_PT_3: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const AES_128_AAD_3: &str = "";
const AES_128_CT_3: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
const AES_128_TAG_3: &str = "4d5c2af327cd64a62cf35abd2ba6fab4";

/// NIST SP 800-38D AES-256-GCM Test Vector 1
const AES_256_KEY_1: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const AES_256_IV_1: &str = "000000000000000000000000";
const AES_256_PT_1: &str = "";
const AES_256_AAD_1: &str = "";
const AES_256_CT_1: &str = "";
const AES_256_TAG_1: &str = "530f8afbc74536b9a963b4f1c4cb738b";

/// NIST SP 800-38D AES-256-GCM Test Vector 2
const AES_256_KEY_2: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const AES_256_IV_2: &str = "000000000000000000000000";
const AES_256_PT_2: &str = "00000000000000000000000000000000";
const AES_256_AAD_2: &str = "";
const AES_256_CT_2: &str = "cea7403d4d606b6e074ec5d3baf39d18";
const AES_256_TAG_2: &str = "d0d1c8a799996bf0265b98b5d48ab919";

/// NIST SP 800-38D AES-256-GCM Test Vector 3
const AES_256_KEY_3: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const AES_256_IV_3: &str = "cafebabefacedbaddecaf888";
const AES_256_PT_3: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const AES_256_AAD_3: &str = "";
const AES_256_CT_3: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
const AES_256_TAG_3: &str = "b094dac5d93471bdec1a502270e3cc6c";

/// Test AES-128-GCM with NIST test vector 1 (empty plaintext)
#[test]
fn test_aes128_gcm_nist_vector_1() {
    let key = decode_hex(AES_128_KEY_1).expect("key decode");
    let nonce = decode_hex(AES_128_IV_1).expect("nonce decode");
    let plaintext = decode_hex(AES_128_PT_1).expect("plaintext decode");
    let aad = decode_hex(AES_128_AAD_1).expect("aad decode");
    let expected_ct = decode_hex(AES_128_CT_1).expect("ciphertext decode");
    let expected_tag = decode_hex(AES_128_TAG_1).expect("tag decode");

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = AesGcm128::new(&key_arr).expect("cipher creation");

    let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, aad_opt).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );
}

/// Test AES-128-GCM with NIST test vector 2 (with plaintext)
#[test]
fn test_aes128_gcm_nist_vector_2() {
    let key = decode_hex(AES_128_KEY_2).expect("key decode");
    let nonce = decode_hex(AES_128_IV_2).expect("nonce decode");
    let plaintext = decode_hex(AES_128_PT_2).expect("plaintext decode");
    let aad = decode_hex(AES_128_AAD_2).expect("aad decode");
    let expected_ct = decode_hex(AES_128_CT_2).expect("ciphertext decode");
    let expected_tag = decode_hex(AES_128_TAG_2).expect("tag decode");

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = AesGcm128::new(&key_arr).expect("cipher creation");

    let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, aad_opt).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );

    // Test decryption
    let decrypted = cipher.decrypt(&nonce_arr, &ct, &tag, aad_opt).expect("decryption");
    assert_eq!(decrypted, plaintext, "Decryption mismatch");
}

/// Test AES-128-GCM with NIST test vector 3 (longer plaintext)
#[test]
fn test_aes128_gcm_nist_vector_3() {
    let key = decode_hex(AES_128_KEY_3).expect("key decode");
    let nonce = decode_hex(AES_128_IV_3).expect("nonce decode");
    let plaintext = decode_hex(AES_128_PT_3).expect("plaintext decode");
    let aad = decode_hex(AES_128_AAD_3).expect("aad decode");
    let expected_ct = decode_hex(AES_128_CT_3).expect("ciphertext decode");
    let expected_tag = decode_hex(AES_128_TAG_3).expect("tag decode");

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = AesGcm128::new(&key_arr).expect("cipher creation");

    let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, aad_opt).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );

    // Test decryption
    let decrypted = cipher.decrypt(&nonce_arr, &ct, &tag, aad_opt).expect("decryption");
    assert_eq!(decrypted, plaintext, "Decryption mismatch");
}

/// Test AES-256-GCM with NIST test vector 1 (empty plaintext)
#[test]
fn test_aes256_gcm_nist_vector_1() {
    let key = decode_hex(AES_256_KEY_1).expect("key decode");
    let nonce = decode_hex(AES_256_IV_1).expect("nonce decode");
    let plaintext = decode_hex(AES_256_PT_1).expect("plaintext decode");
    let aad = decode_hex(AES_256_AAD_1).expect("aad decode");
    let expected_ct = decode_hex(AES_256_CT_1).expect("ciphertext decode");
    let expected_tag = decode_hex(AES_256_TAG_1).expect("tag decode");

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = AesGcm256::new(&key_arr).expect("cipher creation");

    let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, aad_opt).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );
}

/// Test AES-256-GCM with NIST test vector 2 (with plaintext)
#[test]
fn test_aes256_gcm_nist_vector_2() {
    let key = decode_hex(AES_256_KEY_2).expect("key decode");
    let nonce = decode_hex(AES_256_IV_2).expect("nonce decode");
    let plaintext = decode_hex(AES_256_PT_2).expect("plaintext decode");
    let aad = decode_hex(AES_256_AAD_2).expect("aad decode");
    let expected_ct = decode_hex(AES_256_CT_2).expect("ciphertext decode");
    let expected_tag = decode_hex(AES_256_TAG_2).expect("tag decode");

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = AesGcm256::new(&key_arr).expect("cipher creation");

    let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, aad_opt).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );

    // Test decryption
    let decrypted = cipher.decrypt(&nonce_arr, &ct, &tag, aad_opt).expect("decryption");
    assert_eq!(decrypted, plaintext, "Decryption mismatch");
}

/// Test AES-256-GCM with NIST test vector 3 (longer plaintext)
#[test]
fn test_aes256_gcm_nist_vector_3() {
    let key = decode_hex(AES_256_KEY_3).expect("key decode");
    let nonce = decode_hex(AES_256_IV_3).expect("nonce decode");
    let plaintext = decode_hex(AES_256_PT_3).expect("plaintext decode");
    let aad = decode_hex(AES_256_AAD_3).expect("aad decode");
    let expected_ct = decode_hex(AES_256_CT_3).expect("ciphertext decode");
    let expected_tag = decode_hex(AES_256_TAG_3).expect("tag decode");

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = AesGcm256::new(&key_arr).expect("cipher creation");

    let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, aad_opt).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );

    // Test decryption
    let decrypted = cipher.decrypt(&nonce_arr, &ct, &tag, aad_opt).expect("decryption");
    assert_eq!(decrypted, plaintext, "Decryption mismatch");
}

/// Test AES-GCM roundtrip with generated key
#[test]
fn test_aes128_gcm_roundtrip() {
    let key = AesGcm128::generate_key();
    let nonce = AesGcm128::generate_nonce();
    let plaintext = b"Test message for AES-128-GCM roundtrip";
    let aad = b"Additional authenticated data";

    let cipher = AesGcm128::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption");
    let decrypted = cipher.decrypt(&nonce, &ct, &tag, Some(aad)).expect("decryption");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_aes256_gcm_roundtrip() {
    let key = AesGcm256::generate_key();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"Test message for AES-256-GCM roundtrip";
    let aad = b"Additional authenticated data";

    let cipher = AesGcm256::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption");
    let decrypted = cipher.decrypt(&nonce, &ct, &tag, Some(aad)).expect("decryption");

    assert_eq!(decrypted.as_slice(), plaintext);
}

/// Test authentication tag tampering detection
#[test]
fn test_aes_gcm_tag_tampering() {
    let key = AesGcm256::generate_key();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"Test message";

    let cipher = AesGcm256::new(&key).expect("cipher creation");
    let (ct, mut tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");

    // Tamper with tag
    tag[0] ^= 0xFF;

    let result = cipher.decrypt(&nonce, &ct, &tag, None);
    assert!(result.is_err(), "Decryption should fail with tampered tag");
}

/// Test ciphertext tampering detection
#[test]
fn test_aes_gcm_ciphertext_tampering() {
    let key = AesGcm256::generate_key();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"Test message for tampering";

    let cipher = AesGcm256::new(&key).expect("cipher creation");
    let (mut ct, tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");

    // Tamper with ciphertext
    if !ct.is_empty() {
        ct[0] ^= 0xFF;
    }

    let result = cipher.decrypt(&nonce, &ct, &tag, None);
    assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
}

/// Test AAD tampering detection
#[test]
fn test_aes_gcm_aad_tampering() {
    let key = AesGcm256::generate_key();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"Test message";
    let aad = b"Original AAD";
    let tampered_aad = b"Tampered AAD";

    let cipher = AesGcm256::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption");

    let result = cipher.decrypt(&nonce, &ct, &tag, Some(tampered_aad));
    assert!(result.is_err(), "Decryption should fail with tampered AAD");
}

/// Test invalid key length rejection
#[test]
fn test_aes128_invalid_key_length() {
    let short_key = [0u8; 8]; // Wrong size
    let result = AesGcm128::new(&short_key);
    assert!(result.is_err(), "Should reject invalid key length");
}

#[test]
fn test_aes256_invalid_key_length() {
    let short_key = [0u8; 16]; // Wrong size for AES-256
    let result = AesGcm256::new(&short_key);
    assert!(result.is_err(), "Should reject invalid key length");
}

/// Test empty plaintext encryption
#[test]
fn test_aes_gcm_empty_plaintext() {
    let key = AesGcm256::generate_key();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"";

    let cipher = AesGcm256::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");

    assert!(ct.is_empty(), "Ciphertext for empty plaintext should be empty");
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");

    let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).expect("decryption");
    assert!(decrypted.is_empty(), "Decrypted should be empty");
}
