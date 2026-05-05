//! KEM, KDF, and Hybrid-combiner regressions.
//!
//! Covers ML-KEM (FIPS PCT, embedded PK extraction), HKDF / PBKDF2 input
//! validation, hybrid KEM combiner channel-binding, ECDH point validation,
//! and AAD-redaction Debug impls. Reverting any fix must make the
//! corresponding test fail.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]

use latticearc::PqOnlySecretKey;
use latticearc::hybrid::kem_hybrid::{
    HybridKemPublicKey, HybridSharedSecretInputs, derive_hybrid_shared_secret,
};
use latticearc::primitives::kdf::Pbkdf2Params;
use latticearc::primitives::kdf::hkdf::{hkdf_extract, hkdf_simple};
use latticearc::primitives::kem::ecdh::EcdhP256KeyPair;
use latticearc::primitives::kem::{MlKem, MlKemSecurityLevel};

/// ECDH agree() rejects an all-zero-coordinate P-256 PK
/// (defense-in-depth on top of aws-lc-rs).
#[test]
fn ecdh_p256_agree_rejects_all_zero_coordinate_pk() {
    let kp = EcdhP256KeyPair::generate().unwrap();
    let mut bad_pk = vec![0x04u8]; // SEC1 uncompressed prefix
    bad_pk.extend_from_slice(&[0u8; 64]); // all-zero coords
    let result = kp.agree(&bad_pk);
    assert!(result.is_err(), "All-zero P-256 pubkey must be rejected by agree()");
}

// ML-KEM PCT runs inside generate_decapsulation_keypair (hybrid keygen path)

#[test]
fn generate_decapsulation_keypair_runs_pct() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let result = MlKem::generate_decapsulation_keypair(level);
        assert!(result.is_ok(), "generate_decapsulation_keypair must run PCT and succeed");
    }
}

// MlKemSecretKey::embedded_public_key_bytes returns Result on well-formed SK

#[test]
fn embedded_public_key_bytes_returns_result_on_well_formed_sk() {
    let (_pk, sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
    let pk_bytes = sk.embedded_public_key_bytes().expect("well-formed SK must yield embedded PK");
    assert_eq!(pk_bytes.len(), MlKemSecurityLevel::MlKem768.public_key_size());
}

// HybridKemPublicKey::from_bytes rejects wrong-level inner-PK length

#[test]
fn hybrid_pk_rejects_inner_pk_length_mismatch() {
    // Buffer claims Level 5 (level_tag = 3) but carries a Level 3-shaped
    // 1184-byte ML-KEM PK. Pre-fix this parsed and only failed at first encap.
    let mut buf: Vec<u8> = Vec::new();
    buf.push(1); // wire format version
    buf.push(3); // level tag = MlKem1024 / Level 5

    let bogus_ml_kem_pk = vec![0xAAu8; 1184];
    let ml_len = u32::try_from(bogus_ml_kem_pk.len()).unwrap();
    buf.extend_from_slice(&ml_len.to_be_bytes());
    buf.extend_from_slice(&bogus_ml_kem_pk);

    let ecdh_pk = vec![0xBBu8; 32];
    let ed_len = u32::try_from(ecdh_pk.len()).unwrap();
    buf.extend_from_slice(&ed_len.to_be_bytes());
    buf.extend_from_slice(&ecdh_pk);

    let result = HybridKemPublicKey::from_bytes(&buf);
    assert!(
        result.is_err(),
        "HybridKemPublicKey::from_bytes must reject inner-pk length mismatched to security level"
    );
    let _ = MlKemSecurityLevel::MlKem1024;
}

// HKDF: empty IKM rejected (extract + simple)

#[test]
fn hkdf_extract_rejects_empty_ikm() {
    let result = hkdf_extract(Some(b"some-salt-with-real-bytes"), &[]);
    assert!(result.is_err(), "hkdf_extract must reject empty IKM");
}

#[test]
fn hkdf_simple_rejects_empty_ikm() {
    let result = hkdf_simple(&[], 32);
    assert!(result.is_err(), "hkdf_simple must reject empty IKM");
}

// HKDF: explicit Some(&[]) salt is rejected; None still opts into RFC default

#[test]
fn hkdf_extract_rejects_explicit_empty_salt() {
    let result = hkdf_extract(Some(&[]), b"some-non-empty-ikm");
    assert!(
        result.is_err(),
        "hkdf_extract must reject Some(&[]) — caller must use None for the RFC default"
    );
}

#[test]
fn hkdf_extract_accepts_none_salt() {
    let result = hkdf_extract(None, b"some-non-empty-ikm");
    assert!(result.is_ok(), "hkdf_extract must still accept None salt");
}

// PBKDF2 validate() surfaces SP 800-132 §5.1 minimum at construction

#[test]
fn pbkdf2_validate_rejects_short_salt_at_construction() {
    let short_salt = [0xFF; 8]; // below MIN_SALT_LEN of 16
    let result = Pbkdf2Params::with_salt(&short_salt).validate();
    assert!(
        result.is_err(),
        "Pbkdf2Params::validate must reject salts below SP 800-132 §5.1 minimum"
    );
}

#[test]
fn pbkdf2_validate_accepts_proper_params() {
    let salt = [0xFF; 16];
    let result = Pbkdf2Params::with_salt(&salt).validate();
    assert!(result.is_ok(), "Pbkdf2Params::validate must accept properly-formed params");
}

// PqOnlySecretKey: from_sk_bytes derives PK; from_bytes rejects mismatched PK

#[test]
fn pq_only_from_sk_bytes_derives_pk_from_embedded() {
    let (pk, sk) = latticearc::generate_pq_keypair().unwrap();
    let sk_bytes = sk.expose_secret().to_vec();
    let level = sk.security_level();
    let _ = pk;
    let reloaded =
        PqOnlySecretKey::from_sk_bytes(level, &sk_bytes).expect("from_sk_bytes must succeed");
    assert_eq!(reloaded.recipient_pk_bytes().len(), level.public_key_size());
    let _ = MlKemSecurityLevel::MlKem768;
}

#[test]
fn pq_only_from_bytes_rejects_mismatched_pk() {
    let (_pk, sk) = latticearc::generate_pq_keypair().unwrap();
    let sk_bytes = sk.expose_secret().to_vec();
    let level = sk.security_level();
    let bogus_pk = vec![0u8; level.public_key_size()];
    let result = PqOnlySecretKey::from_bytes(level, &sk_bytes, &bogus_pk);
    assert!(
        result.is_err(),
        "from_bytes must reject a PK that does not match the SK's embedded PK"
    );
}

// Hybrid combiner binds ml_kem_static_pk (HPKE §5.1 channel binding both legs)

#[test]
fn hybrid_combiner_includes_ml_kem_static_pk() {
    let ml_kem_ss = [0x01u8; 32];
    let ecdh_ss = [0x02u8; 32];
    let ecdh_static = [0x03u8; 32];
    let ml_kem_static_a = [0x04u8; 32];
    let ml_kem_static_b = [0x05u8; 32];
    let ephemeral = [0x06u8; 32];
    let kem_ct = [0x07u8; 32];

    let s_a = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        ecdh_static_pk: &ecdh_static,
        ml_kem_static_pk: &ml_kem_static_a,
        ephemeral_pk: &ephemeral,
        kem_ct: &kem_ct,
    })
    .unwrap();
    let s_b = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: &ml_kem_ss,
        ecdh_ss: &ecdh_ss,
        ecdh_static_pk: &ecdh_static,
        ml_kem_static_pk: &ml_kem_static_b,
        ephemeral_pk: &ephemeral,
        kem_ct: &kem_ct,
    })
    .unwrap();
    assert_ne!(
        s_a.expose_secret(),
        s_b.expose_secret(),
        "swapping ml_kem_static_pk must change the combiner output"
    );
}

// HybridEncryptionContext Debug redacts AAD

#[test]
fn hybrid_encryption_context_debug_redacts_aad() {
    use latticearc::hybrid::encrypt_hybrid::HybridEncryptionContext;
    let ctx = HybridEncryptionContext::with_aad(
        b"sensitive-request-id-12345-and-some-tracing-cookie".to_vec(),
    );
    let debug = format!("{:?}", ctx);
    assert!(
        !debug.contains("sensitive-request-id-12345"),
        "HybridEncryptionContext Debug must NOT include AAD bytes; got: {debug}"
    );
    assert!(
        debug.contains("aad_len"),
        "HybridEncryptionContext Debug should expose aad_len, not aad bytes; got: {debug}"
    );
}
