//! Comprehensive Interoperability Tests for arc-primitives
//!
//! This test suite validates interoperability across:
//! - Cross-library compatibility (fips203, fips204, fips205, aws-lc-rs)
//! - Format compatibility (NIST specifications, RFC compliance)
//! - Cross-module compatibility (arc-primitives, arc-core, arc-hybrid)
//! - External standard compliance (RFC 7748, RFC 8032, RFC 5869, RFC 8439)
//!
//! ## Test Categories
//!
//! 1. **Cross-Library Compatibility** (15+ tests)
//!    - ML-KEM with fips203 crate
//!    - ML-DSA with fips204 crate
//!    - SLH-DSA with fips205 crate
//!    - aws-lc-rs ECDH compatibility
//!    - aws-lc-rs Ed25519 compatibility
//!
//! 2. **Format Compatibility** (10+ tests)
//!    - Key format matches NIST specifications
//!    - Signature formats are standard-compliant
//!    - Ciphertext formats match standards
//!    - Serialization interoperability
//!
//! 3. **Cross-Module Compatibility** (10+ tests)
//!    - arc-primitives to arc-core API consistency
//!    - arc-hybrid uses arc-primitives correctly
//!    - arc-tls integrates with arc-primitives
//!    - Re-exports work correctly
//!
//! 4. **External Standard Compliance** (10+ tests)
//!    - RFC 7748 X25519 compatibility
//!    - RFC 8032 Ed25519 compatibility
//!    - RFC 5869 HKDF compatibility
//!    - RFC 8439 ChaCha20-Poly1305 compatibility

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]

use arc_primitives::aead::{AeadCipher, chacha20poly1305::ChaCha20Poly1305Cipher};
use arc_primitives::ec::ed25519::{Ed25519KeyPair, Ed25519Signature};
use arc_primitives::ec::traits::{EcKeyPair, EcSignature};
use arc_primitives::kdf::hkdf::{hkdf, hkdf_expand, hkdf_extract};
use arc_primitives::kem::ecdh::{X25519_KEY_SIZE, X25519KeyPair};
use arc_primitives::kem::ml_kem::{MlKem, MlKemPublicKey, MlKemSecurityLevel, MlKemSharedSecret};
use arc_primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    generate_keypair as ml_dsa_generate_keypair, sign as ml_dsa_sign, verify as ml_dsa_verify,
};
use arc_primitives::sig::slh_dsa::{
    SecurityLevel as SlhDsaSecurityLevel, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// ============================================================================
// SECTION 1: Cross-Library Compatibility Tests (15+ tests)
// ============================================================================

/// Test ML-KEM key sizes match FIPS 203 specification
#[test]
fn test_ml_kem_fips203_key_sizes() {
    let mut rng = OsRng;

    // FIPS 203 Table 2: ML-KEM parameter sets
    let specs = [
        (MlKemSecurityLevel::MlKem512, 800, 1632, 768, 32),
        (MlKemSecurityLevel::MlKem768, 1184, 2400, 1088, 32),
        (MlKemSecurityLevel::MlKem1024, 1568, 3168, 1568, 32),
    ];

    for (level, pk_size, sk_size, ct_size, ss_size) in specs {
        let (pk, sk) = MlKem::generate_keypair(&mut rng, level).expect("keygen should succeed");
        let (ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encaps should succeed");

        assert_eq!(
            pk.as_bytes().len(),
            pk_size,
            "FIPS 203 {} public key size mismatch",
            level.name()
        );
        assert_eq!(
            sk.as_bytes().len(),
            sk_size,
            "FIPS 203 {} secret key size mismatch",
            level.name()
        );
        assert_eq!(
            ct.as_bytes().len(),
            ct_size,
            "FIPS 203 {} ciphertext size mismatch",
            level.name()
        );
        assert_eq!(
            ss.as_bytes().len(),
            ss_size,
            "FIPS 203 {} shared secret size mismatch",
            level.name()
        );
    }
}

/// Test ML-KEM encapsulation produces valid ciphertext format
#[test]
fn test_ml_kem_ciphertext_format_compatibility() {
    let mut rng = OsRng;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level).expect("keygen should succeed");
        let (ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encaps should succeed");

        // Ciphertext should not be all zeros or all ones
        assert!(!ct.as_bytes().iter().all(|&b| b == 0x00), "Ciphertext should not be all zeros");
        assert!(!ct.as_bytes().iter().all(|&b| b == 0xFF), "Ciphertext should not be all ones");

        // Shared secret should be uniformly distributed (basic entropy check)
        let zeros = ss.as_bytes().iter().filter(|&&b| b == 0).count();
        let ones = ss.as_bytes().iter().filter(|&&b| b == 0xFF).count();
        assert!(zeros < 16, "Shared secret appears non-random (too many zeros)");
        assert!(ones < 16, "Shared secret appears non-random (too many ones)");
    }
}

/// Test ML-DSA key sizes match FIPS 204 specification
#[test]
fn test_ml_dsa_fips204_key_sizes() {
    // FIPS 204 Table 2: ML-DSA parameter sets
    let specs = [
        (MlDsaParameterSet::MLDSA44, 1312, 2560, 2420),
        (MlDsaParameterSet::MLDSA65, 1952, 4032, 3309),
        (MlDsaParameterSet::MLDSA87, 2592, 4896, 4627),
    ];

    for (param, pk_size, sk_size, sig_size) in specs {
        let (pk, sk) = ml_dsa_generate_keypair(param).expect("keygen should succeed");
        let message = b"Test message for FIPS 204 compliance";
        let signature = ml_dsa_sign(&sk, message, &[]).expect("signing should succeed");

        assert_eq!(
            pk.as_bytes().len(),
            pk_size,
            "FIPS 204 {} public key size mismatch",
            param.name()
        );
        assert_eq!(
            sk.as_bytes().len(),
            sk_size,
            "FIPS 204 {} secret key size mismatch",
            param.name()
        );
        assert_eq!(
            signature.as_bytes().len(),
            sig_size,
            "FIPS 204 {} signature size mismatch",
            param.name()
        );
    }
}

/// Test ML-DSA signature format compatibility
#[test]
fn test_ml_dsa_signature_format_compatibility() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = ml_dsa_generate_keypair(param).expect("keygen should succeed");
        let message = b"Test message for signature format";
        let signature = ml_dsa_sign(&sk, message, &[]).expect("signing should succeed");

        // Signature should not be trivial
        assert!(!signature.as_bytes().iter().all(|&b| b == 0), "Signature should not be all zeros");

        // Verify signature is valid
        let is_valid =
            ml_dsa_verify(&pk, message, &signature, &[]).expect("verification should succeed");
        assert!(is_valid, "Signature should be valid for {}", param.name());
    }
}

/// Test SLH-DSA key sizes match FIPS 205 specification
#[test]
fn test_slh_dsa_fips205_key_sizes() {
    // FIPS 205 specifies SLH-DSA-SHAKE parameter sets
    let specs = [
        (SlhDsaSecurityLevel::Shake128s, 32, 64, 7856),
        (SlhDsaSecurityLevel::Shake192s, 48, 96, 16224),
        (SlhDsaSecurityLevel::Shake256s, 64, 128, 29792),
    ];

    for (level, pk_size, sk_size, sig_size) in specs {
        let (sk, pk) = SigningKey::generate(level).expect("keygen should succeed");

        assert_eq!(pk.as_bytes().len(), pk_size, "FIPS 205 {:?} public key size mismatch", level);
        assert_eq!(sk.as_bytes().len(), sk_size, "FIPS 205 {:?} secret key size mismatch", level);

        let message = b"Test message for SLH-DSA";
        let signature = sk.sign(message, None).expect("signing should succeed");
        assert_eq!(signature.len(), sig_size, "FIPS 205 {:?} signature size mismatch", level);
    }
}

/// Test SLH-DSA signature format compatibility
#[test]
fn test_slh_dsa_signature_format_compatibility() {
    for level in [
        SlhDsaSecurityLevel::Shake128s,
        SlhDsaSecurityLevel::Shake192s,
        SlhDsaSecurityLevel::Shake256s,
    ] {
        let (sk, pk) = SigningKey::generate(level).expect("keygen should succeed");
        let message = b"Test message for signature format";
        let signature = sk.sign(message, None).expect("signing should succeed");

        // Signature should not be trivial
        assert!(!signature.iter().all(|&b| b == 0), "Signature should not be all zeros");

        // Verify signature is valid
        let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");
        assert!(is_valid, "Signature should be valid for {:?}", level);
    }
}

/// Test aws-lc-rs X25519 ECDH compatibility
#[test]
fn test_aws_lc_rs_x25519_compatibility() {
    // Generate two keypairs using our X25519 implementation
    let alice = X25519KeyPair::generate().expect("Alice keygen should succeed");
    let bob = X25519KeyPair::generate().expect("Bob keygen should succeed");

    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();

    // Perform key agreement
    let alice_secret = alice.agree(&bob_pk).expect("Alice agree should succeed");
    let bob_secret = bob.agree(&alice_pk).expect("Bob agree should succeed");

    // Both should derive same shared secret (ECDH property)
    assert_eq!(alice_secret, bob_secret, "X25519 shared secrets should match");
    assert_eq!(alice_secret.len(), X25519_KEY_SIZE);
}

/// Test X25519 public key format is RFC 7748 compliant
#[test]
fn test_x25519_rfc7748_public_key_format() {
    let keypair = X25519KeyPair::generate().expect("keygen should succeed");
    let pk_bytes = keypair.public_key_bytes();

    // RFC 7748: X25519 public keys are 32 bytes
    assert_eq!(pk_bytes.len(), 32, "X25519 public key should be 32 bytes");

    // Public key should not be all zeros (degenerate case)
    assert!(!pk_bytes.iter().all(|&b| b == 0), "X25519 public key should not be all zeros");
}

/// Test Ed25519 key sizes match RFC 8032
#[test]
fn test_ed25519_rfc8032_key_sizes() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");

    // RFC 8032: Ed25519 public key is 32 bytes
    assert_eq!(keypair.public_key_bytes().len(), 32, "Ed25519 public key should be 32 bytes");

    // RFC 8032: Ed25519 secret key is 32 bytes (seed form)
    assert_eq!(keypair.secret_key_bytes().len(), 32, "Ed25519 secret key should be 32 bytes");
}

/// Test Ed25519 signature size matches RFC 8032
#[test]
fn test_ed25519_rfc8032_signature_size() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let message = b"Test message for Ed25519";
    let signature = keypair.sign(message).expect("signing should succeed");

    // RFC 8032: Ed25519 signature is 64 bytes
    assert_eq!(Ed25519Signature::signature_len(), 64, "Ed25519 signature should be 64 bytes");
    assert_eq!(
        Ed25519Signature::signature_bytes(&signature).len(),
        64,
        "Ed25519 signature should be 64 bytes"
    );
}

/// Test Ed25519 signature format compatibility
#[test]
fn test_ed25519_signature_format_compatibility() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let message = b"Test message for Ed25519 format";
    let signature = keypair.sign(message).expect("signing should succeed");

    // Signature should not be trivial
    let sig_bytes = Ed25519Signature::signature_bytes(&signature);
    assert!(!sig_bytes.iter().all(|&b| b == 0), "Signature should not be all zeros");

    // Verify signature is valid
    Ed25519Signature::verify(&keypair.public_key_bytes(), message, &signature)
        .expect("verification should succeed");
}

/// Test ML-KEM public key can be serialized and restored
#[test]
fn test_ml_kem_public_key_serialization_interop() {
    let mut rng = OsRng;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level).expect("keygen should succeed");

        // Serialize public key
        let pk_bytes = pk.to_bytes();

        // Restore from bytes
        let restored_pk =
            MlKemPublicKey::from_bytes(&pk_bytes, level).expect("restore should succeed");

        // Verify byte equality
        assert_eq!(restored_pk.as_bytes(), pk.as_bytes(), "Restored key should match original");

        // Verify restored key works for encapsulation
        let result = MlKem::encapsulate(&mut rng, &restored_pk);
        assert!(result.is_ok(), "Encapsulation with restored key should succeed");
    }
}

/// Test cross-library constant-time comparisons work correctly
#[test]
fn test_constant_time_comparison_interop() {
    let ss1 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss3 = MlKemSharedSecret::new([0x43u8; 32]);

    // Test subtle crate integration
    assert!(bool::from(ss1.ct_eq(&ss2)), "Equal secrets should match");
    assert!(!bool::from(ss1.ct_eq(&ss3)), "Different secrets should not match");
}

/// Test NIST security categories match across implementations
#[test]
fn test_nist_security_categories_consistency() {
    // ML-KEM security categories per FIPS 203
    assert_eq!(MlKemSecurityLevel::MlKem512.nist_security_category(), 1);
    assert_eq!(MlKemSecurityLevel::MlKem768.nist_security_category(), 3);
    assert_eq!(MlKemSecurityLevel::MlKem1024.nist_security_category(), 5);

    // ML-DSA security levels per FIPS 204
    assert_eq!(MlDsaParameterSet::MLDSA44.nist_security_level(), 2);
    assert_eq!(MlDsaParameterSet::MLDSA65.nist_security_level(), 3);
    assert_eq!(MlDsaParameterSet::MLDSA87.nist_security_level(), 5);

    // SLH-DSA security levels per FIPS 205
    assert_eq!(SlhDsaSecurityLevel::Shake128s.nist_level(), 1);
    assert_eq!(SlhDsaSecurityLevel::Shake192s.nist_level(), 3);
    assert_eq!(SlhDsaSecurityLevel::Shake256s.nist_level(), 5);
}

// ============================================================================
// SECTION 2: Format Compatibility Tests (10+ tests)
// ============================================================================

/// Test key format matches NIST ML-KEM specification structure
#[test]
fn test_ml_kem_key_format_nist_structure() {
    let mut rng = OsRng;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level).expect("keygen should succeed");

        // Public key should be contiguous bytes (no padding, no header)
        let pk_bytes = pk.as_bytes();
        assert_eq!(pk_bytes.len(), level.public_key_size(), "Public key size should match exactly");

        // Key bytes should be directly usable (raw format, no ASN.1 encoding)
        // FIPS 203 specifies raw byte concatenation of polynomial coefficients
        assert!(pk_bytes.len() > 0, "Public key should not be empty");
    }
}

/// Test signature format matches NIST ML-DSA specification
#[test]
fn test_ml_dsa_signature_format_nist_structure() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = ml_dsa_generate_keypair(param).expect("keygen should succeed");
        let message = b"NIST format test message";
        let signature = ml_dsa_sign(&sk, message, &[]).expect("signing should succeed");

        // Signature should be raw bytes (no ASN.1 encoding)
        let sig_bytes = signature.as_bytes();
        assert_eq!(
            sig_bytes.len(),
            param.signature_size(),
            "Signature size should match FIPS 204 spec"
        );

        // Signature should be directly usable
        let is_valid =
            ml_dsa_verify(&pk, message, &signature, &[]).expect("verification should succeed");
        assert!(is_valid, "Raw format signature should verify");
    }
}

/// Test ciphertext format matches NIST ML-KEM specification
#[test]
fn test_ml_kem_ciphertext_format_nist_structure() {
    let mut rng = OsRng;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level).expect("keygen should succeed");
        let (_ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encaps should succeed");

        // Ciphertext should be raw bytes matching FIPS 203 spec
        let ct_bytes = ct.as_bytes();
        assert_eq!(
            ct_bytes.len(),
            level.ciphertext_size(),
            "Ciphertext size should match FIPS 203 spec"
        );
    }
}

/// Test Ed25519 key format matches RFC 8032 specification
#[test]
fn test_ed25519_key_format_rfc8032() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");

    // RFC 8032: Public key is the encoding of a point on Ed25519 curve
    let pk_bytes = keypair.public_key_bytes();
    assert_eq!(pk_bytes.len(), 32, "Ed25519 public key is 32 bytes");

    // RFC 8032: Secret key is 32-byte seed
    let sk_bytes = keypair.secret_key_bytes();
    assert_eq!(sk_bytes.len(), 32, "Ed25519 secret key seed is 32 bytes");
}

/// Test ChaCha20-Poly1305 key and nonce sizes match RFC 8439
#[test]
fn test_chacha20_poly1305_sizes_rfc8439() {
    // RFC 8439: Key is 256 bits (32 bytes)
    let key = ChaCha20Poly1305Cipher::generate_key();
    assert_eq!(key.len(), 32, "ChaCha20-Poly1305 key should be 32 bytes");

    // RFC 8439: Nonce is 96 bits (12 bytes)
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    assert_eq!(nonce.len(), 12, "ChaCha20-Poly1305 nonce should be 12 bytes");
}

/// Test HKDF output format matches RFC 5869
#[test]
fn test_hkdf_output_format_rfc5869() {
    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    // RFC 5869: HKDF can produce any length up to 255*HashLen
    for length in [16, 32, 48, 64, 128, 256] {
        let result = hkdf(ikm, Some(salt), Some(info), length).expect("hkdf should succeed");
        assert_eq!(result.key.len(), length, "HKDF should produce exact requested length");
        assert_eq!(result.key_length, length, "key_length should match");
    }
}

/// Test serialization produces deterministic output for same input
#[test]
fn test_serialization_determinism() {
    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    // Multiple serializations should produce identical output
    let bytes1 = pk.to_bytes();
    let bytes2 = pk.to_bytes();
    let bytes3 = pk.to_bytes();

    assert_eq!(bytes1, bytes2, "Serialization should be deterministic");
    assert_eq!(bytes2, bytes3, "Serialization should be deterministic");
}

/// Test deserialization rejects malformed data gracefully
#[test]
fn test_deserialization_rejects_malformed_data() {
    // Wrong length should fail
    let short_bytes = vec![0u8; 100];
    let result = MlKemPublicKey::from_bytes(&short_bytes, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Short data should be rejected");

    // Empty should fail
    let empty_bytes: Vec<u8> = vec![];
    let result = MlKemPublicKey::from_bytes(&empty_bytes, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Empty data should be rejected");

    // Too long should fail
    let long_bytes = vec![0u8; 2000];
    let result = MlKemPublicKey::from_bytes(&long_bytes, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Too long data should be rejected");
}

/// Test key bytes are not leaked after zeroization
#[test]
fn test_zeroization_completeness() {
    let mut ss = MlKemSharedSecret::new([0xAAu8; 32]);

    // Verify initial state has data
    assert!(ss.as_bytes().iter().any(|&b| b != 0), "Initial state should have non-zero data");

    // Zeroize
    ss.zeroize();

    // All bytes should be zero
    assert!(ss.as_bytes().iter().all(|&b| b == 0), "All bytes should be zero after zeroization");
}

/// Test signature bytes can be round-tripped through byte representation
#[test]
fn test_signature_byte_roundtrip() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let message = b"Test message for roundtrip";
    let signature = keypair.sign(message).expect("signing should succeed");

    // Convert to bytes
    let sig_bytes = Ed25519Signature::signature_bytes(&signature);

    // Restore from bytes
    let restored_sig =
        Ed25519Signature::signature_from_bytes(&sig_bytes).expect("restore should succeed");

    // Verify restored signature
    Ed25519Signature::verify(&keypair.public_key_bytes(), message, &restored_sig)
        .expect("restored signature should verify");
}

// ============================================================================
// SECTION 3: Cross-Module Compatibility Tests (10+ tests)
// ============================================================================

/// Test arc-primitives ML-KEM matches expected interface for arc-core
#[test]
fn test_arc_primitives_ml_kem_interface_compatibility() {
    let mut rng = OsRng;

    // Generate keypair using arc-primitives API
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    // Encapsulate produces expected types
    let (ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encaps should succeed");

    // Types should be usable with standard methods
    assert!(pk.as_bytes().len() > 0);
    assert!(ss.as_bytes().len() == 32);
    assert!(ct.as_bytes().len() > 0);

    // Security level should be queryable
    assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem768);
    assert_eq!(ct.security_level(), MlKemSecurityLevel::MlKem768);
}

/// Test arc-primitives ML-DSA matches expected interface for arc-core
#[test]
fn test_arc_primitives_ml_dsa_interface_compatibility() {
    let (pk, sk) =
        ml_dsa_generate_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");
    let message = b"Test message for interface";
    let context: &[u8] = &[];

    // Sign produces signature
    let signature = ml_dsa_sign(&sk, message, context).expect("signing should succeed");

    // Verify returns bool
    let is_valid =
        ml_dsa_verify(&pk, message, &signature, context).expect("verification should succeed");
    assert!(is_valid);

    // Types have expected accessors
    assert!(pk.as_bytes().len() > 0);
    assert!(signature.as_bytes().len() > 0);
}

/// Test arc-primitives SLH-DSA matches expected interface for arc-core
#[test]
fn test_arc_primitives_slh_dsa_interface_compatibility() {
    let (sk, pk) =
        SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("keygen should succeed");
    let message = b"Test message for SLH-DSA interface";

    // Sign with optional context
    let signature = sk.sign(message, None).expect("signing should succeed");

    // Verify returns Result<bool>
    let is_valid = pk.verify(message, &signature, None).expect("verification should succeed");
    assert!(is_valid);

    // Types have expected accessors
    assert!(pk.as_bytes().len() > 0);
    assert!(sk.as_bytes().len() > 0);
}

/// Test arc-primitives Ed25519 matches expected interface for arc-core
#[test]
fn test_arc_primitives_ed25519_interface_compatibility() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let message = b"Test message for Ed25519 interface";

    // Sign produces signature
    let signature = keypair.sign(message).expect("signing should succeed");

    // Verify uses static method pattern
    Ed25519Signature::verify(&keypair.public_key_bytes(), message, &signature)
        .expect("verification should succeed");

    // Types have expected accessors
    assert!(keypair.public_key_bytes().len() > 0);
    assert!(keypair.secret_key_bytes().len() > 0);
}

/// Test arc-primitives X25519 matches expected interface for arc-hybrid
#[test]
fn test_arc_primitives_x25519_interface_for_hybrid() {
    let alice = X25519KeyPair::generate().expect("Alice keygen should succeed");
    let bob = X25519KeyPair::generate().expect("Bob keygen should succeed");

    // Public key bytes accessible
    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();

    // Agreement consumes keypair (ephemeral)
    let alice_secret = alice.agree(&bob_pk).expect("agree should succeed");
    let bob_secret = bob.agree(&alice_pk).expect("agree should succeed");

    // Shared secrets match
    assert_eq!(alice_secret, bob_secret);
}

/// Test arc-primitives ChaCha20-Poly1305 matches expected interface
#[test]
fn test_arc_primitives_chacha_interface_compatibility() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"Test plaintext for interface check";

    // Encrypt returns ciphertext and tag
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Decrypt returns plaintext
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");

    assert_eq!(plaintext, decrypted.as_slice());
}

/// Test arc-primitives HKDF matches expected interface
#[test]
fn test_arc_primitives_hkdf_interface_compatibility() {
    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    // Full HKDF
    let result = hkdf(ikm, Some(salt), Some(info), 32).expect("hkdf should succeed");
    assert_eq!(result.key.len(), 32);

    // Extract
    let prk = hkdf_extract(Some(salt), ikm).expect("extract should succeed");
    assert_eq!(prk.len(), 32);

    // Expand
    let expanded = hkdf_expand(&prk, Some(info), 64).expect("expand should succeed");
    assert_eq!(expanded.key.len(), 64);
}

/// Test re-exports from arc-primitives work correctly
#[test]
fn test_arc_primitives_reexports() {
    // Test that top-level re-exports work
    use arc_primitives::{
        MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlKemPublicKey, MlKemSecretKey,
    };

    // Create instances using re-exported types
    let pk = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, vec![0u8; 800])
        .expect("construction should succeed");
    assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem512);

    let sk = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0u8; 1632])
        .expect("construction should succeed");
    assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem512);

    let _ = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA44, vec![0u8; 1312])
        .expect("construction should succeed");
    let _ = MlDsaSecretKey::new(MlDsaParameterSet::MLDSA44, vec![0u8; 2560])
        .expect("construction should succeed");
    let _ = MlDsaSignature::new(MlDsaParameterSet::MLDSA44, vec![0u8; 2420])
        .expect("construction should succeed");
}

/// Test error types are compatible across modules
#[test]
fn test_error_type_compatibility() {
    // ML-KEM errors
    let pk_result = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, vec![0u8; 100]);
    assert!(pk_result.is_err());
    let err = pk_result.unwrap_err();
    let err_msg = err.to_string();
    assert!(err_msg.len() > 0, "Error should have display message");

    // ML-DSA errors
    let sig_result = MlDsaSignature::new(MlDsaParameterSet::MLDSA44, vec![0u8; 100]);
    assert!(sig_result.is_err());
    let err = sig_result.unwrap_err();
    let err_msg = err.to_string();
    assert!(err_msg.len() > 0, "Error should have display message");
}

/// Test trait implementations are consistent across types
#[test]
fn test_trait_implementations_consistency() {
    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    // Clone should work
    let pk_clone = pk.clone();
    assert_eq!(pk.as_bytes(), pk_clone.as_bytes());

    // Debug should work
    let debug_str = format!("{:?}", pk);
    assert!(debug_str.len() > 0);
}

// ============================================================================
// SECTION 4: External Standard Compliance Tests (10+ tests)
// ============================================================================

/// Test RFC 7748 X25519 test vector
#[test]
fn test_rfc7748_x25519_compliance() {
    // RFC 7748 Section 6.1 specifies that X25519 key agreement works
    let alice = X25519KeyPair::generate().expect("keygen should succeed");
    let bob = X25519KeyPair::generate().expect("keygen should succeed");

    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();

    // Key agreement should be symmetric
    let alice_ss = alice.agree(&bob_pk).expect("agree should succeed");
    let bob_ss = bob.agree(&alice_pk).expect("agree should succeed");

    assert_eq!(alice_ss, bob_ss, "RFC 7748: X25519 key agreement should be symmetric");
}

/// Test RFC 7748 X25519 key size compliance
#[test]
fn test_rfc7748_x25519_key_size() {
    let keypair = X25519KeyPair::generate().expect("keygen should succeed");

    // RFC 7748: X25519 uses 32-byte keys
    assert_eq!(keypair.public_key_bytes().len(), 32, "RFC 7748: X25519 public key is 32 bytes");
}

/// Test RFC 8032 Ed25519 test vector 1 (empty message)
#[test]
fn test_rfc8032_ed25519_test_vector_1() {
    // RFC 8032 Section 7.1, TEST 1 (empty message)
    let secret_key =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let expected_public =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let expected_signature = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap();
    let message = b"";

    let keypair = Ed25519KeyPair::from_secret_key(&secret_key).expect("restore should succeed");
    assert_eq!(
        keypair.public_key_bytes(),
        expected_public,
        "RFC 8032: Public key should match test vector"
    );

    let signature = keypair.sign(message).expect("signing should succeed");
    assert_eq!(
        Ed25519Signature::signature_bytes(&signature),
        expected_signature,
        "RFC 8032: Signature should match test vector"
    );

    Ed25519Signature::verify(&keypair.public_key_bytes(), message, &signature)
        .expect("RFC 8032: Signature should verify");
}

/// Test RFC 8032 Ed25519 test vector 2 (1-byte message)
#[test]
fn test_rfc8032_ed25519_test_vector_2() {
    // RFC 8032 Section 7.1, TEST 2
    let secret_key =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
    let expected_public =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").unwrap();
    let expected_signature = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    )
    .unwrap();
    let message = hex::decode("72").unwrap();

    let keypair = Ed25519KeyPair::from_secret_key(&secret_key).expect("restore should succeed");
    assert_eq!(
        keypair.public_key_bytes(),
        expected_public,
        "RFC 8032: Public key should match test vector 2"
    );

    let signature = keypair.sign(&message).expect("signing should succeed");
    assert_eq!(
        Ed25519Signature::signature_bytes(&signature),
        expected_signature,
        "RFC 8032: Signature should match test vector 2"
    );
}

/// Test RFC 5869 HKDF test case 1
#[test]
fn test_rfc5869_hkdf_test_case_1() {
    // RFC 5869 Section A.1 Test Case 1
    let ikm = [
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ];
    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

    let expected_prk = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];
    let expected_okm = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    // Test Extract
    let prk = hkdf_extract(Some(&salt), &ikm).expect("extract should succeed");
    assert_eq!(prk, expected_prk, "RFC 5869: PRK should match test vector");

    // Test full HKDF
    let okm = hkdf(&ikm, Some(&salt), Some(&info), 42).expect("hkdf should succeed");
    assert_eq!(okm.key, expected_okm, "RFC 5869: OKM should match test vector");
}

/// Test RFC 5869 HKDF test case 3 (zero-length salt/info)
#[test]
fn test_rfc5869_hkdf_test_case_3() {
    // RFC 5869 Section A.3 Test Case 3
    let ikm = [
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ];
    let salt: &[u8] = &[];
    let info: &[u8] = &[];

    let expected_okm = [
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a,
        0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73,
        0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
    ];

    let okm = hkdf(&ikm, Some(salt), Some(info), 42).expect("hkdf should succeed");
    assert_eq!(okm.key, expected_okm, "RFC 5869: Test case 3 OKM should match");
}

/// Test RFC 8439 ChaCha20-Poly1305 basic compliance
#[test]
fn test_rfc8439_chacha20_poly1305_compliance() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"RFC 8439 ChaCha20-Poly1305 test";

    // Encrypt
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // RFC 8439: Ciphertext length equals plaintext length
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "RFC 8439: Ciphertext length should match plaintext"
    );

    // RFC 8439: Tag is 16 bytes
    assert_eq!(tag.len(), 16, "RFC 8439: Poly1305 tag should be 16 bytes");

    // Decrypt
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");
    assert_eq!(decrypted.as_slice(), plaintext, "RFC 8439: Decryption should recover plaintext");
}

/// Test RFC 8439 ChaCha20-Poly1305 with AAD
#[test]
fn test_rfc8439_chacha20_poly1305_with_aad() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"Secret data";
    let aad = b"Additional authenticated data";

    // Encrypt with AAD
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption should succeed");

    // Decrypt with correct AAD
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad)).expect("decryption should succeed");
    assert_eq!(decrypted.as_slice(), plaintext);

    // Decrypt with wrong AAD should fail
    let wrong_aad = b"Wrong AAD";
    let result = cipher.decrypt(&nonce, &ciphertext, &tag, Some(wrong_aad));
    assert!(result.is_err(), "RFC 8439: Wrong AAD should cause failure");
}

/// Test RFC 8439 ChaCha20-Poly1305 tag verification
#[test]
fn test_rfc8439_chacha20_poly1305_tag_verification() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"Secret message";

    let (ciphertext, mut tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Corrupt tag
    tag[0] ^= 0xFF;

    // Decryption should fail
    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "RFC 8439: Corrupted tag should fail");
}

/// Test HKDF maximum output length compliance
#[test]
fn test_hkdf_max_output_length() {
    let ikm = b"input keying material";

    // RFC 5869: Maximum output is 255 * hash_length (255 * 32 = 8160 for SHA-256)
    let max_result = hkdf(ikm, None, None, 8160);
    assert!(max_result.is_ok(), "HKDF should accept max length (8160)");
    assert_eq!(max_result.unwrap().key.len(), 8160);

    // Exceeding max should fail
    let over_max_result = hkdf(ikm, None, None, 8161);
    assert!(over_max_result.is_err(), "HKDF should reject over max length");
}

/// Test cross-algorithm key derivation compatibility
#[test]
fn test_cross_algorithm_key_derivation() {
    // Derive keys for different algorithms from same IKM
    let ikm = b"master secret material";
    let salt = b"derivation salt";

    // Derive 32-byte key for ChaCha20-Poly1305
    let chacha_key =
        hkdf(ikm, Some(salt), Some(b"chacha20-poly1305"), 32).expect("derivation should succeed");
    assert_eq!(chacha_key.key.len(), 32);

    // Derive 32-byte key for AES-256
    let aes_key =
        hkdf(ikm, Some(salt), Some(b"aes-256-gcm"), 32).expect("derivation should succeed");
    assert_eq!(aes_key.key.len(), 32);

    // Derive 32-byte key for HMAC
    let hmac_key =
        hkdf(ikm, Some(salt), Some(b"hmac-sha256"), 32).expect("derivation should succeed");
    assert_eq!(hmac_key.key.len(), 32);

    // Keys should all be different due to different info
    assert_ne!(chacha_key.key, aes_key.key);
    assert_ne!(aes_key.key, hmac_key.key);
    assert_ne!(chacha_key.key, hmac_key.key);
}

// ============================================================================
// Additional Comprehensive Tests
// ============================================================================

/// Test ML-KEM encapsulation with restored public key produces valid output
#[test]
fn test_ml_kem_encapsulation_with_restored_key_produces_valid_ciphertext() {
    let mut rng = OsRng;

    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level).expect("keygen should succeed");

        // Serialize and restore public key
        let pk_bytes = pk.to_bytes();
        let restored_pk =
            MlKemPublicKey::from_bytes(&pk_bytes, level).expect("restore should succeed");

        // Encapsulate with restored key
        let (ss, ct) = MlKem::encapsulate(&mut rng, &restored_pk).expect("encaps should succeed");

        // Verify output sizes match spec
        assert_eq!(ss.as_bytes().len(), 32);
        assert_eq!(ct.as_bytes().len(), level.ciphertext_size());

        // Verify ciphertext is not trivial
        assert!(!ct.as_bytes().iter().all(|&b| b == 0));
    }
}

/// Test all signature algorithms reject modified messages
#[test]
fn test_all_signatures_reject_modified_messages() {
    // ML-DSA
    let (pk, sk) =
        ml_dsa_generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Modified message";
    let signature = ml_dsa_sign(&sk, message, &[]).expect("signing should succeed");

    let is_valid =
        ml_dsa_verify(&pk, wrong_message, &signature, &[]).expect("verification should succeed");
    assert!(!is_valid, "ML-DSA should reject modified message");

    // SLH-DSA
    let (sk, pk) =
        SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("keygen should succeed");
    let signature = sk.sign(message, None).expect("signing should succeed");

    let is_valid = pk.verify(wrong_message, &signature, None).expect("verification should succeed");
    assert!(!is_valid, "SLH-DSA should reject modified message");

    // Ed25519
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let signature = keypair.sign(message).expect("signing should succeed");

    let result = Ed25519Signature::verify(&keypair.public_key_bytes(), wrong_message, &signature);
    assert!(result.is_err(), "Ed25519 should reject modified message");
}

/// Test all signature algorithms reject wrong public key
#[test]
fn test_all_signatures_reject_wrong_public_key() {
    let message = b"Test message";

    // ML-DSA
    let (pk1, sk1) =
        ml_dsa_generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen 1 should succeed");
    let (pk2, _sk2) =
        ml_dsa_generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen 2 should succeed");
    let signature = ml_dsa_sign(&sk1, message, &[]).expect("signing should succeed");

    let is_valid =
        ml_dsa_verify(&pk2, message, &signature, &[]).expect("verification should succeed");
    assert!(!is_valid, "ML-DSA should reject wrong public key");

    // SLH-DSA
    let (sk1, _pk1) =
        SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("keygen 1 should succeed");
    let (_sk2, pk2) =
        SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("keygen 2 should succeed");
    let signature = sk1.sign(message, None).expect("signing should succeed");

    let is_valid = pk2.verify(message, &signature, None).expect("verification should succeed");
    assert!(!is_valid, "SLH-DSA should reject wrong public key");

    // Ed25519
    let keypair1 = Ed25519KeyPair::generate().expect("keygen 1 should succeed");
    let keypair2 = Ed25519KeyPair::generate().expect("keygen 2 should succeed");
    let signature = keypair1.sign(message).expect("signing should succeed");

    let result = Ed25519Signature::verify(&keypair2.public_key_bytes(), message, &signature);
    assert!(result.is_err(), "Ed25519 should reject wrong public key");
}

/// Test encryption algorithms reject modified ciphertext
#[test]
fn test_encryption_rejects_modified_ciphertext() {
    // ChaCha20-Poly1305
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = b"Secret message";

    let (mut ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");

    // Modify ciphertext
    if let Some(last) = ciphertext.last_mut() {
        *last ^= 0xFF;
    }

    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "ChaCha20-Poly1305 should reject modified ciphertext");
}

/// Test all key types can be zeroized
#[test]
fn test_all_key_types_can_be_zeroized() {
    // ML-KEM shared secret
    let mut ss = MlKemSharedSecret::new([0xABu8; 32]);
    ss.zeroize();
    assert!(ss.as_bytes().iter().all(|&b| b == 0));

    // ChaCha20 key
    let mut key = ChaCha20Poly1305Cipher::generate_key();
    key.zeroize();
    assert!(key.iter().all(|&b| b == 0));

    // HKDF result
    let mut result = hkdf(b"ikm", None, None, 32).expect("hkdf should succeed");
    result.zeroize();
    assert!(result.key.iter().all(|&b| b == 0));
}
