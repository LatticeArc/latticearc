#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for AES-GCM encryption/decryption
//!
//! Tests that encrypt_aes_gcm/decrypt_aes_gcm roundtrip correctly
//! with arbitrary plaintext data.

use latticearc::unified_api::zero_trust::SecurityMode;
use latticearc::unified_api::{
    VerifiedSession, decrypt_aes_gcm, encrypt_aes_gcm, generate_keypair,
};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

// `VerifiedSession::establish` runs a full challenge/response handshake
// (real keypair + signatures) and is too heavy to repeat per fuzz
// iteration. Build it once on first access via `LazyLock` so each
// fuzz iteration only pays for the AEAD operation. `Option<_>` so a
// transient init failure (entropy depletion, etc.) skips the
// Verified-mode test for that fuzz process rather than panicking the
// harness.
static VERIFIED_SESSION: LazyLock<Option<VerifiedSession>> = LazyLock::new(|| {
    let (pk, sk) = generate_keypair().ok()?;
    VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).ok()
});

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key + some plaintext
    if data.len() < 33 {
        return;
    }

    // Use first 32 bytes as key, rest as plaintext
    let key = &data[..32];
    let plaintext = &data[32..];

    // Test 1: Unverified mode roundtrip
    if let Ok(encrypted) = encrypt_aes_gcm(plaintext, key, SecurityMode::Unverified) {
        if let Ok(decrypted) = decrypt_aes_gcm(&encrypted, key, SecurityMode::Unverified) {
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }

    // Test 2: Verified mode roundtrip — exercises `mode.validate()`'s
    // trust-level + session-lifetime branches, which the Unverified
    // mode never touches.
    if let Some(session) = VERIFIED_SESSION.as_ref() {
        let mode = SecurityMode::Verified(session);
        if let Ok(encrypted) = encrypt_aes_gcm(plaintext, key, mode) {
            if let Ok(decrypted) = decrypt_aes_gcm(&encrypted, key, mode) {
                assert_eq!(plaintext, decrypted.as_slice());
            }
        }
    }
});
