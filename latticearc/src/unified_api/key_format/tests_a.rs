//! Unit tests for `key_format`: passphrase encryption/decryption,
//! encrypted-envelope negative validation, `encryption_aad` byte-layout
//! stability, `KeyAlgorithm` serde/canonical-name roundtrips, the
//! `not_after` lifecycle field, `KeyType`/`KeyData` serde and roundtrip
//! behavior, JSON/CBOR roundtrips, `validate()` rejection paths, `Debug`
//! redaction, and metadata roundtrips. Split from the second half
//! (`tests_b`) purely to keep each file under the project's soft line-count
//! target; there is no topical boundary at the split point.
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

use super::*;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

// ------------------------------------------------------------------
// Passphrase-encrypted key roundtrip
// ------------------------------------------------------------------

fn sample_single_key() -> PortableKey {
    // AES-256 symmetric key (Single variant).
    let raw = [0x11u8; 32];
    PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&raw))
}

fn sample_composite_key() -> PortableKey {
    // Hybrid ML-KEM-768 + X25519 public key lookalike (Composite variant).
    let pq = vec![0x22u8; 1184];
    let classical = vec![0x33u8; 32];
    PortableKey::new(
        KeyAlgorithm::HybridMlKem768X25519,
        KeyType::Public,
        KeyData::from_composite(&pq, &classical),
    )
}

#[test]
fn test_encrypt_with_passphrase_single_roundtrip() {
    let mut key = sample_single_key();
    let plain_raw = key.key_data().decode_raw().unwrap();
    let passphrase = b"correct horse battery staple";

    key.encrypt_with_passphrase(passphrase).unwrap();
    assert!(key.is_encrypted());
    assert!(key.key_data().decode_raw().is_err());

    key.validate().expect("encrypted envelope must validate");

    key.decrypt_with_passphrase(passphrase).unwrap();
    assert!(!key.is_encrypted());
    assert_eq!(key.key_data().decode_raw().unwrap(), plain_raw);
}

#[test]
fn test_encrypt_with_passphrase_composite_roundtrip() {
    let mut key = sample_composite_key();
    let (pq_plain, cl_plain) = key.key_data().decode_composite().unwrap();
    let passphrase = b"hunter2-but-stronger";

    key.encrypt_with_passphrase(passphrase).unwrap();
    assert!(key.is_encrypted());
    assert!(key.key_data().decode_composite().is_err());

    key.decrypt_with_passphrase(passphrase).unwrap();
    let (pq_out, cl_out) = key.key_data().decode_composite().unwrap();
    assert_eq!(pq_out, pq_plain);
    assert_eq!(cl_out, cl_plain);
}

#[test]
fn test_encrypt_with_passphrase_wrong_passphrase_fails() {
    let mut key = sample_single_key();
    key.encrypt_with_passphrase(b"correct passphrase").unwrap();

    let err =
        key.decrypt_with_passphrase(b"wrong passphrase").expect_err("wrong passphrase must fail");
    // The error must NOT disclose whether the passphrase was wrong vs the
    // envelope was corrupted — the message is a fixed opaque phrase.
    // Compare the EXACT string so a future code change that diverges
    // the two paths (e.g. distinct "PBKDF2 failure" vs "tag mismatch"
    // errors) will break this test.
    assert_eq!(
        err.to_string(),
        "Invalid key: Passphrase-protected key unwrap failed \
         (wrong passphrase or corrupted envelope)"
    );
}

/// Corrupting the ciphertext bytes must produce the **same** opaque
/// error as providing a wrong passphrase. If decrypt ever gained a
/// distinct code path for "tag failure" vs "post-KDF AES init failure",
/// a passphrase oracle would open up — this test pins the error string
/// to catch that regression.
#[test]
fn test_encrypt_with_passphrase_corrupted_ciphertext_matches_wrong_passphrase_error() {
    let mut key = sample_single_key();
    key.encrypt_with_passphrase(b"correct passphrase").unwrap();

    // Decode, flip the middle byte, re-encode. Round-tripping through
    // base64 keeps the envelope structurally valid so the corruption
    // surfaces at AEAD verification rather than at the base64 decode
    // pre-check in validate_encrypted_envelope_fields.
    let KeyData::Encrypted { ciphertext, .. } = &mut key.key_data else {
        panic!("expected encrypted variant");
    };
    let mut raw = BASE64_ENGINE.decode(ciphertext.as_str()).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0x01;
    *ciphertext = BASE64_ENGINE.encode(&raw);

    let err = key
        .decrypt_with_passphrase(b"correct passphrase")
        .expect_err("corrupted ciphertext must fail");
    // Exact-match: the error must be byte-identical to the wrong-passphrase error.
    assert_eq!(
        err.to_string(),
        "Invalid key: Passphrase-protected key unwrap failed \
         (wrong passphrase or corrupted envelope)"
    );
}

#[test]
fn test_encrypt_with_passphrase_empty_rejected() {
    let mut key = sample_single_key();
    assert!(key.encrypt_with_passphrase(b"").is_err());
}

#[test]
fn test_encrypt_with_passphrase_double_encrypt_rejected() {
    let mut key = sample_single_key();
    key.encrypt_with_passphrase(b"once").unwrap();
    assert!(key.encrypt_with_passphrase(b"twice").is_err());
}

#[test]
fn test_decrypt_with_passphrase_on_plaintext_fails() {
    let mut key = sample_single_key();
    assert!(key.decrypt_with_passphrase(b"anything").is_err());
}

#[test]
fn test_encrypted_key_json_roundtrip() {
    let mut key = sample_single_key();
    let plain_raw = key.key_data().decode_raw().unwrap();
    key.encrypt_with_passphrase(b"json roundtrip").unwrap();

    let json = key.to_json().unwrap();
    // Sanity: the envelope should be valid JSON and visibly contain the
    // envelope marker "kdf" so we know serde picked the Encrypted variant.
    assert!(json.contains("\"kdf\""));
    assert!(json.contains("PBKDF2-HMAC-SHA256"));

    let mut reloaded = PortableKey::from_json(&json).unwrap();
    assert!(reloaded.is_encrypted());
    reloaded.decrypt_with_passphrase(b"json roundtrip").unwrap();
    assert_eq!(reloaded.key_data().decode_raw().unwrap(), plain_raw);
}

#[test]
fn test_encrypted_key_aad_binds_algorithm() {
    // An encrypted blob must not decrypt after the enclosing
    // PortableKey's algorithm field has been swapped — AEAD
    // authentication must fail.
    let mut key = sample_single_key();
    key.encrypt_with_passphrase(b"aad binding").unwrap();

    let tampered_data = key.key_data.clone_for_transmission();
    let mut tampered = PortableKey::new(KeyAlgorithm::ChaCha20, KeyType::Symmetric, tampered_data);

    assert!(tampered.decrypt_with_passphrase(b"aad binding").is_err());
}

#[test]
fn test_encrypted_key_aad_binds_key_type() {
    // Companion to `test_encrypted_key_aad_binds_algorithm`: the AAD also
    // covers `key_type`, so a swap from Symmetric → Secret must fail
    // AEAD verification even when the algorithm is unchanged.
    let mut key = sample_single_key();
    key.encrypt_with_passphrase(b"aad binding").unwrap();

    let tampered_data = key.key_data.clone_for_transmission();
    // Swap Symmetric → Secret. `Aes256` isn't a valid algorithm for a
    // Secret key at load time, but `decrypt_with_passphrase` runs the
    // AEAD check before any such validation, so the test still exercises
    // the AAD binding path before the type validator would reject the
    // combination.
    let mut tampered = PortableKey::new(KeyAlgorithm::Aes256, KeyType::Secret, tampered_data);

    assert!(tampered.decrypt_with_passphrase(b"aad binding").is_err());
}

// --- Encrypted envelope negative validation tests ---

/// Snapshot of a freshly-encrypted envelope's fields, used to build
/// tampered copies that exercise each rejection branch of
/// `validate_encrypted_envelope_fields`. Cloning via this helper
/// sidesteps `KeyData`'s `Drop` impl, which forbids partial moves.
#[derive(Clone)]
struct EnvelopeSnapshot {
    enc: u32,
    kdf: String,
    kdf_iterations: u32,
    kdf_salt: String,
    aead: String,
    nonce: String,
    ciphertext: String,
}

impl EnvelopeSnapshot {
    fn capture(key: &PortableKey) -> Option<Self> {
        match &key.key_data {
            KeyData::Encrypted { enc, kdf, kdf_iterations, kdf_salt, aead, nonce, ciphertext } => {
                Some(Self {
                    enc: *enc,
                    kdf: kdf.clone(),
                    kdf_iterations: *kdf_iterations,
                    kdf_salt: kdf_salt.clone(),
                    aead: aead.clone(),
                    nonce: nonce.clone(),
                    ciphertext: ciphertext.clone(),
                })
            }
            _ => None,
        }
    }

    fn into_key_data(self) -> KeyData {
        KeyData::Encrypted {
            enc: self.enc,
            kdf: self.kdf,
            kdf_iterations: self.kdf_iterations,
            kdf_salt: self.kdf_salt,
            aead: self.aead,
            nonce: self.nonce,
            ciphertext: self.ciphertext,
        }
    }
}

/// Build a valid encrypted sample key and return it alongside a snapshot
/// of its envelope fields.
fn make_valid_encrypted_key() -> (PortableKey, EnvelopeSnapshot) {
    let mut key = sample_single_key();
    key.encrypt_with_passphrase(b"envelope validation").unwrap();
    let snapshot = EnvelopeSnapshot::capture(&key).expect("sample key is freshly encrypted");
    (key, snapshot)
}

#[test]
fn test_validate_rejects_wrong_envelope_version() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.enc = 99;
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("wrong envelope version must be rejected");
    assert!(err.to_string().contains("Unsupported encrypted key envelope version 99"));
}

#[test]
fn test_validate_rejects_superseded_envelope_version() {
    // A v2 envelope carries an older AEAD AAD layout. It must be
    // rejected with a distinct, actionable "re-protect" error rather
    // than the opaque wrong-passphrase failure the version field
    // exists to prevent.
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.enc = 2;
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("superseded envelope version must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("v2 encrypted-key envelope"), "got: {msg}");
    assert!(msg.contains("Re-protect"), "got: {msg}");
}

#[test]
fn test_validate_rejects_unknown_kdf() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.kdf = "scrypt".to_string();
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("unknown KDF must be rejected");
    assert!(err.to_string().contains("Unsupported KDF"));
}

#[test]
fn test_validate_rejects_unknown_aead() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.aead = "ChaCha20-Poly1305".to_string();
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("unknown AEAD must be rejected");
    assert!(err.to_string().contains("Unsupported AEAD"));
}

#[test]
fn test_validate_rejects_too_few_pbkdf2_iterations() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.kdf_iterations = 50_000; // below PBKDF2_MIN_ITERATIONS
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("low iteration count must be rejected");
    assert!(err.to_string().contains("PBKDF2 iteration count 50000 below minimum"));
}

#[test]
fn test_validate_rejects_short_salt() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.kdf_salt = BASE64_ENGINE.encode([0u8; 8]); // 8 < PBKDF2_MIN_SALT_LEN
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("short salt must be rejected");
    assert!(err.to_string().contains("PBKDF2 salt length 8 below minimum"));
}

#[test]
fn test_validate_rejects_wrong_nonce_length() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.nonce = BASE64_ENGINE.encode([0u8; 8]); // 8 != AES_GCM_NONCE_LEN
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("wrong nonce length must be rejected");
    assert!(err.to_string().contains("AES-GCM nonce length 8"));
}

#[test]
fn test_validate_rejects_ciphertext_shorter_than_tag() {
    let (mut key, mut snapshot) = make_valid_encrypted_key();
    snapshot.ciphertext = BASE64_ENGINE.encode([0u8; 4]); // 4 < AES_GCM_TAG_LEN
    key.key_data = snapshot.into_key_data();
    let err = key.validate().expect_err("short ciphertext must be rejected");
    assert!(err.to_string().contains("Encrypted key ciphertext shorter than AES-GCM tag"));
}

/// Pinned byte layout for the encrypted-envelope AAD.
///
/// This is the on-the-wire AEAD AAD used for every passphrase-encrypted
/// key. Any change to the layout — including a change to
/// `KeyAlgorithm::canonical_name`, `KeyType::canonical_name`, the
/// envelope constants, the field ordering, or the separator bytes —
/// invalidates every existing encrypted key file. This test pins the
/// exact bytes for a fixed fixture so an accidental drift shows up in
/// CI before landing.
#[test]
fn test_encryption_aad_byte_layout_is_stable() {
    let salt = [0xAA_u8; 16];
    let metadata: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let aad = PortableKey::encryption_aad(
        1,
        KeyAlgorithm::Aes256,
        KeyType::Symmetric,
        "PBKDF2-HMAC-SHA256",
        600_000,
        &salt,
        "AES-256-GCM",
        &metadata,
    )
    .unwrap();

    // Empty BTreeMap canonicalizes to "{}" in JSON.
    let metadata_json = serde_json::to_vec(&metadata).unwrap();
    assert_eq!(&metadata_json, b"{}");

    // label bumped v2 → v3 and `aead` field gains a
    // null terminator (matching every other string field). Any
    // future drift will fail this pin; deliberate format changes
    // require updating the expected bytes here AND bumping the
    // label suffix.
    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(b"latticearc-lpk-v3-enc");
    expected.push(0);
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(b"aes-256");
    expected.push(0);
    expected.extend_from_slice(b"symmetric");
    expected.push(0);
    expected.extend_from_slice(b"PBKDF2-HMAC-SHA256");
    expected.push(0);
    expected.extend_from_slice(&600_000u32.to_be_bytes());
    expected.extend_from_slice(&16u32.to_be_bytes());
    expected.extend_from_slice(&salt);
    expected.extend_from_slice(b"AES-256-GCM");
    expected.push(0);
    expected.extend_from_slice(&u32::try_from(metadata_json.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(&metadata_json);

    assert_eq!(aad, expected);
}

#[test]
fn test_encryption_aad_metadata_change_breaks_aad() {
    // The whole point of binding metadata into the AAD: a change to
    // any metadata field must produce a different AAD, which in turn
    // makes the AEAD tag fail. This test pins that property.
    let salt = [0xAA_u8; 16];
    let mut a: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    a.insert("ml_kem_pk".to_string(), serde_json::Value::String("AAAAAA".to_string()));
    let mut b: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    b.insert("ml_kem_pk".to_string(), serde_json::Value::String("BBBBBB".to_string()));
    let aad_a = PortableKey::encryption_aad(
        1,
        KeyAlgorithm::HybridMlKem768X25519,
        KeyType::Secret,
        "PBKDF2-HMAC-SHA256",
        600_000,
        &salt,
        "AES-256-GCM",
        &a,
    )
    .unwrap();
    let aad_b = PortableKey::encryption_aad(
        1,
        KeyAlgorithm::HybridMlKem768X25519,
        KeyType::Secret,
        "PBKDF2-HMAC-SHA256",
        600_000,
        &salt,
        "AES-256-GCM",
        &b,
    )
    .unwrap();
    assert_ne!(aad_a, aad_b, "swapping ml_kem_pk in metadata must change AAD");
}

/// Pin every `KeyAlgorithm` and `KeyType` canonical name against its
/// serde-rename string. If they diverge, the canonical_name used in the
/// AAD will silently mismatch the on-disk `algorithm`/`key_type` fields
/// of existing keys. Failing this test means one of the constants must
/// be updated deliberately and all existing encrypted keys must be
/// re-wrapped.
#[test]
fn test_canonical_names_match_serde_rename() {
    fn serde_name<T: Serialize>(t: &T) -> String {
        let s = serde_json::to_string(t).unwrap();
        // Strip the surrounding quotes produced by JSON string encoding.
        s.trim_matches('"').to_string()
    }
    let algorithms = [
        KeyAlgorithm::MlKem512,
        KeyAlgorithm::MlKem768,
        KeyAlgorithm::MlKem1024,
        KeyAlgorithm::MlDsa44,
        KeyAlgorithm::MlDsa65,
        KeyAlgorithm::MlDsa87,
        KeyAlgorithm::SlhDsaShake128s,
        KeyAlgorithm::SlhDsaShake192s,
        KeyAlgorithm::SlhDsaShake256s,
        KeyAlgorithm::FnDsa512,
        KeyAlgorithm::FnDsa1024,
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::X25519,
        KeyAlgorithm::Aes256,
        KeyAlgorithm::ChaCha20,
        KeyAlgorithm::Secp256k1,
        KeyAlgorithm::HybridMlKem512X25519,
        KeyAlgorithm::HybridMlKem768X25519,
        KeyAlgorithm::HybridMlKem1024X25519,
        KeyAlgorithm::HybridMlDsa44Ed25519,
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyAlgorithm::HybridMlDsa87Ed25519,
    ];
    for alg in algorithms {
        assert_eq!(alg.canonical_name(), serde_name(&alg), "canonical_name drift for {alg:?}");
    }
    for kt in [KeyType::Public, KeyType::Secret, KeyType::Symmetric] {
        assert_eq!(kt.canonical_name(), serde_name(&kt), "canonical_name drift for {kt:?}");
    }
}

// --- KeyAlgorithm serde roundtrip ---

#[test]
fn test_key_algorithm_serde_all_variants_roundtrip() {
    let variants = [
        (KeyAlgorithm::MlKem512, "\"ml-kem-512\""),
        (KeyAlgorithm::MlKem768, "\"ml-kem-768\""),
        (KeyAlgorithm::MlKem1024, "\"ml-kem-1024\""),
        (KeyAlgorithm::MlDsa44, "\"ml-dsa-44\""),
        (KeyAlgorithm::MlDsa65, "\"ml-dsa-65\""),
        (KeyAlgorithm::MlDsa87, "\"ml-dsa-87\""),
        (KeyAlgorithm::SlhDsaShake128s, "\"slh-dsa-shake-128s\""),
        (KeyAlgorithm::SlhDsaShake192s, "\"slh-dsa-shake-192s\""),
        (KeyAlgorithm::SlhDsaShake256s, "\"slh-dsa-shake-256s\""),
        (KeyAlgorithm::FnDsa512, "\"fn-dsa-512\""),
        (KeyAlgorithm::FnDsa1024, "\"fn-dsa-1024\""),
        (KeyAlgorithm::Ed25519, "\"ed25519\""),
        (KeyAlgorithm::X25519, "\"x25519\""),
        (KeyAlgorithm::Aes256, "\"aes-256\""),
        (KeyAlgorithm::ChaCha20, "\"chacha20\""),
        (KeyAlgorithm::Secp256k1, "\"secp256k1\""),
        (KeyAlgorithm::HybridMlKem768X25519, "\"hybrid-ml-kem-768-x25519\""),
        (KeyAlgorithm::HybridMlKem512X25519, "\"hybrid-ml-kem-512-x25519\""),
        (KeyAlgorithm::HybridMlKem1024X25519, "\"hybrid-ml-kem-1024-x25519\""),
        (KeyAlgorithm::HybridMlDsa65Ed25519, "\"hybrid-ml-dsa-65-ed25519\""),
        (KeyAlgorithm::HybridMlDsa44Ed25519, "\"hybrid-ml-dsa-44-ed25519\""),
        (KeyAlgorithm::HybridMlDsa87Ed25519, "\"hybrid-ml-dsa-87-ed25519\""),
    ];

    for (variant, expected_json) in &variants {
        let json = serde_json::to_string(variant).unwrap();
        assert_eq!(&json, expected_json, "serialize {:?}", variant);

        let deserialized: KeyAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, *variant, "roundtrip {:?}", variant);
    }
}

#[test]
fn test_key_algorithm_is_hybrid_returns_correct_bool_succeeds() {
    assert!(KeyAlgorithm::HybridMlKem768X25519.is_hybrid());
    assert!(KeyAlgorithm::HybridMlDsa65Ed25519.is_hybrid());
    assert!(!KeyAlgorithm::MlKem768.is_hybrid());
    assert!(!KeyAlgorithm::Aes256.is_hybrid());
}

#[test]
fn test_key_algorithm_is_symmetric_returns_correct_bool_succeeds() {
    assert!(KeyAlgorithm::Aes256.is_symmetric());
    assert!(KeyAlgorithm::ChaCha20.is_symmetric());
    assert!(!KeyAlgorithm::MlKem768.is_symmetric());
}

// --- Secp256k1 variant (added 0.8.4) ---

#[test]
fn test_secp256k1_canonical_name() {
    assert_eq!(KeyAlgorithm::Secp256k1.canonical_name(), "secp256k1");
    assert_eq!(KeyAlgorithm::from_canonical_name("secp256k1"), Some(KeyAlgorithm::Secp256k1));
    assert_eq!(
        KeyAlgorithm::from_canonical_name("SECP256K1"),
        Some(KeyAlgorithm::Secp256k1),
        "from_canonical_name is case-insensitive"
    );
}

#[test]
fn test_secp256k1_keyalgorithm_classification_returns_classical() {
    assert!(KeyAlgorithm::Secp256k1.is_signature());
    assert!(!KeyAlgorithm::Secp256k1.is_kem());
    assert!(!KeyAlgorithm::Secp256k1.is_symmetric());
    assert!(!KeyAlgorithm::Secp256k1.is_hybrid());
    assert_eq!(
        KeyAlgorithm::Secp256k1.nist_security_level(),
        crate::types::types::SecurityLevel::Standard,
    );
}

// --- not_after lifecycle field (added 0.8.4) ---

#[test]
fn test_not_after_default_is_none() {
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    assert!(key.not_after().is_none());
    assert!(!key.is_expired());
}

#[test]
fn test_not_after_set_and_query() {
    let mut key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let future = Utc::now() + chrono::Duration::hours(1);
    let past = Utc::now() - chrono::Duration::hours(1);

    key.set_not_after(Some(future));
    assert_eq!(key.not_after(), Some(future));
    assert!(!key.is_expired_at(Utc::now()));

    key.set_not_after(Some(past));
    assert!(key.is_expired_at(Utc::now()));

    key.set_not_after(None);
    assert!(key.not_after().is_none());
    assert!(!key.is_expired_at(Utc::now()));
}

#[test]
fn test_not_after_json_roundtrip() {
    let mut key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let expiry = DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
    key.set_not_after(Some(expiry));

    let json = key.to_json().expect("serialize");
    assert!(json.contains("not_after"), "JSON must contain not_after field");
    let restored = PortableKey::from_json(&json).expect("deserialize");
    assert_eq!(restored.not_after(), Some(expiry));
}

#[test]
fn test_not_after_omitted_when_none_in_json() {
    // skip_serializing_if = "Option::is_none" must keep the wire format
    // backward-compatible with pre-0.8.4 keys (no not_after field at all).
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let json = key.to_json().expect("serialize");
    assert!(
        !json.contains("not_after"),
        "JSON must NOT contain not_after when None (preserves pre-0.8.4 wire shape)"
    );
}

#[test]
fn test_not_after_cbor_roundtrip() {
    let mut key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let expiry = DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
    key.set_not_after(Some(expiry));

    let cbor = key.to_cbor().expect("serialize");
    let restored = PortableKey::from_cbor(&cbor).expect("deserialize");
    assert_eq!(restored.not_after(), Some(expiry));
}

#[test]
fn test_clone_for_transmission_preserves_not_after() {
    let mut key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let expiry = Utc::now() + chrono::Duration::days(30);
    key.set_not_after(Some(expiry));

    let cloned = key.clone_for_transmission();
    assert_eq!(cloned.not_after(), Some(expiry));
}

#[test]
fn test_ct_eq_distinguishes_not_after() {
    use subtle::ConstantTimeEq;
    let mut a =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let mut b = a.clone_for_transmission();

    let expiry = Utc::now() + chrono::Duration::days(30);
    a.set_not_after(Some(expiry));
    // b still has not_after = None; ct_eq must report inequality.
    assert!(!bool::from(a.ct_eq(&b)));

    b.set_not_after(Some(expiry));
    // Now both have the same expiry; the rest of the key is identical.
    assert!(bool::from(a.ct_eq(&b)));
}

// --- KeyType serde ---

#[test]
fn test_key_type_serde_roundtrip() {
    for (variant, expected) in [
        (KeyType::Public, "\"public\""),
        (KeyType::Secret, "\"secret\""),
        (KeyType::Symmetric, "\"symmetric\""),
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, expected);
        let back: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

// --- KeyData ---

#[test]
fn test_key_data_single_roundtrip() {
    let original = vec![1u8, 2, 3, 4];
    let kd = KeyData::from_raw(&original);
    let decoded = kd.decode_raw().unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_key_data_composite_roundtrip() {
    let pq = vec![0xAA; 32];
    let cl = vec![0xBB; 32];
    let kd = KeyData::from_composite(&pq, &cl);
    let (pq2, cl2) = kd.decode_composite().unwrap();
    assert_eq!(pq2, pq);
    assert_eq!(cl2, cl);
}

#[test]
fn test_key_data_single_decode_composite_fails() {
    let kd = KeyData::from_raw(&[1, 2, 3]);
    assert!(kd.decode_composite().is_err());
}

#[test]
fn test_key_data_composite_decode_raw_fails() {
    let kd = KeyData::from_composite(&[1], &[2]);
    assert!(kd.decode_raw().is_err());
}

#[test]
fn test_key_data_debug_redacts_secret_content_succeeds() {
    let kd = KeyData::from_raw(&[0xDE, 0xAD]);
    let debug = format!("{:?}", kd);
    assert!(!debug.contains("3q0"), "Debug should not contain base64 key material");
    assert!(debug.contains("[...]"));
}

// --- JSON roundtrip ---

#[test]
fn test_json_roundtrip_ml_kem_768_public_roundtrip() {
    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Public,
        KeyData::from_raw(&vec![0xCC; 1184]),
    );
    let json = key.to_json().unwrap();
    let restored = PortableKey::from_json(&json).unwrap();

    assert_eq!(restored.version(), 1);
    assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);
    assert_eq!(restored.key_type(), KeyType::Public);
    assert_eq!(restored.key_data().decode_raw().unwrap().len(), 1184);
}

#[test]
fn test_json_roundtrip_aes_symmetric_roundtrip() {
    let key =
        PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&[0u8; 32]));
    let json = key.to_json().unwrap();
    let restored = PortableKey::from_json(&json).unwrap();
    assert_eq!(restored.algorithm(), KeyAlgorithm::Aes256);
    assert_eq!(restored.key_type(), KeyType::Symmetric);
}

#[test]
fn test_json_roundtrip_hybrid_kem_roundtrip() {
    let key = PortableKey::new(
        KeyAlgorithm::HybridMlKem768X25519,
        KeyType::Secret,
        KeyData::from_composite(&vec![0xAA; 2400], &vec![0xBB; 32]),
    );
    let json = key.to_json().unwrap();
    let restored = PortableKey::from_json(&json).unwrap();
    assert_eq!(restored.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
    let (pq, cl) = restored.key_data().decode_composite().unwrap();
    assert_eq!(pq.len(), 2400);
    assert_eq!(cl.len(), 32);
}

// --- CBOR roundtrip ---

#[test]
fn test_cbor_roundtrip_ml_kem_768_roundtrip() {
    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Public,
        KeyData::from_raw(&vec![0xCC; 1184]),
    );
    let cbor = key.to_cbor().unwrap();
    let restored = PortableKey::from_cbor(&cbor).unwrap();

    assert_eq!(restored.version(), 1);
    assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);
    assert_eq!(restored.key_data().decode_raw().unwrap().len(), 1184);
}

#[test]
fn test_cbor_roundtrip_hybrid_sig_roundtrip() {
    let key = PortableKey::new(
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Secret,
        KeyData::from_composite(&vec![0xCC; 1952], &vec![0xDD; 32]),
    );
    let cbor = key.to_cbor().unwrap();
    let restored = PortableKey::from_cbor(&cbor).unwrap();
    assert_eq!(restored.algorithm(), KeyAlgorithm::HybridMlDsa65Ed25519);
    assert_eq!(restored.key_type(), KeyType::Secret);
}

#[test]
fn test_cbor_smaller_than_json_is_correct() {
    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Public,
        KeyData::from_raw(&vec![0xAA; 1184]),
    );
    let json_bytes = key.to_json().unwrap().len();
    let cbor_bytes = key.to_cbor().unwrap().len();
    assert!(
        cbor_bytes < json_bytes,
        "CBOR ({cbor_bytes}) should be smaller than JSON ({json_bytes})"
    );
}

#[test]
fn test_cbor_json_cross_format_consistency_roundtrip() {
    let key = PortableKey::new(
        KeyAlgorithm::MlDsa65,
        KeyType::Public,
        KeyData::from_raw(&vec![0xBB; 1952]),
    );
    let json = key.to_json().unwrap();
    let cbor = key.to_cbor().unwrap();

    let from_json = PortableKey::from_json(&json).unwrap();
    let from_cbor = PortableKey::from_cbor(&cbor).unwrap();

    assert_eq!(from_json.algorithm(), from_cbor.algorithm());
    assert_eq!(from_json.key_type(), from_cbor.key_type());
    assert_eq!(
        from_json.key_data().decode_raw().unwrap(),
        from_cbor.key_data().decode_raw().unwrap()
    );
}

// --- Validation ---

#[test]
fn test_validate_symmetric_wrong_key_type_fails() {
    let key =
        PortableKey::new(KeyAlgorithm::Aes256, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    assert!(key.validate().is_err());
}

#[test]
fn test_validate_non_symmetric_with_symmetric_type_fails() {
    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Symmetric,
        KeyData::from_raw(&vec![0u8; 1184]),
    );
    assert!(key.validate().is_err());
}

#[test]
fn test_validate_hybrid_with_single_data_fails() {
    let key = PortableKey::new(
        KeyAlgorithm::HybridMlKem768X25519,
        KeyType::Public,
        KeyData::from_raw(&[0u8; 32]),
    );
    assert!(key.validate().is_err());
}

#[test]
fn test_validate_non_hybrid_with_composite_data_fails() {
    let key = PortableKey::new(
        KeyAlgorithm::MlKem768,
        KeyType::Public,
        KeyData::from_composite(&[0u8; 32], &[0u8; 32]),
    );
    assert!(key.validate().is_err());
}

#[test]
fn test_validate_bad_base64_fails() {
    let key = PortableKey {
        version: 1,
        use_case: None,
        security_level: None,
        algorithm: KeyAlgorithm::Aes256,
        key_type: KeyType::Symmetric,
        key_data: KeyData::Single { raw: "not-valid-base64!!!".to_string() },
        created: Utc::now(),
        metadata: BTreeMap::new(),
        not_after: None,
    };
    assert!(key.validate().is_err());
}

// --- Debug redaction ---

#[test]
fn test_debug_redacts_secret_key_content_succeeds() {
    let key = PortableKey::new(
        KeyAlgorithm::MlDsa65,
        KeyType::Secret,
        KeyData::from_raw(&[0xDE, 0xAD, 0xBE, 0xEF]),
    );
    let debug = format!("{:?}", key);
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("3q2+7w"));
}

#[test]
fn test_debug_shows_public_key_type_in_output_succeeds() {
    let key =
        PortableKey::new(KeyAlgorithm::MlDsa65, KeyType::Public, KeyData::from_raw(&[0xDE, 0xAD]));
    let debug = format!("{:?}", key);
    assert!(debug.contains("[key data]"));
    assert!(!debug.contains("REDACTED"));
}

// --- Metadata ---

#[test]
fn test_metadata_roundtrip_via_json_roundtrip() {
    let mut key =
        PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&[0u8; 32]));
    key.set_label("Production signing key").unwrap();
    key.set_metadata("custom_field".to_string(), serde_json::json!(42)).unwrap();

    let json = key.to_json().unwrap();
    let restored = PortableKey::from_json(&json).unwrap();

    assert_eq!(restored.label(), Some("Production signing key"));
    assert_eq!(restored.metadata().get("custom_field"), Some(&serde_json::json!(42)));
}

#[test]
fn test_metadata_omitted_when_empty_in_json_succeeds() {
    let key =
        PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
    let json = key.to_json().unwrap();
    assert!(!json.contains("metadata"));
}
