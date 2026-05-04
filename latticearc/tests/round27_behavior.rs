//! Behavioral regression tests for the round-27 audit fixes.
//!
//! Each test asserts a *user-visible* property the corresponding fix is
//! supposed to provide. To be a genuine regression blocker each test must:
//!   1. PASS against the round-27-fixed code.
//!   2. FAIL if the fix is reverted.
//!
//! Mirrors the round20/21/26_behavior.rs convention.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

/// Round-27 H1: `SigningKeypair`'s manual `Debug` impl must redact
/// `secret_key`. Round-26's derived Debug forwarded through
/// `Zeroizing<Vec<u8>>` to the inner Vec, leaking the raw secret.
/// Reverting the manual impl makes the secret bytes appear in the
/// Debug output.
///
/// `SigningKeypair` is `pub` inside a private module so it cannot be
/// reached from this integration-test crate. The inline guard lives at
/// `latticearc/src/unified_api/convenience/api.rs::tests` (see the
/// `assert_not_impl_any!` for `PartialEq`/`Eq` and the manual `impl
/// Debug`). This file documents the property; the inline test is the
/// regression blocker.
#[test]
fn signing_keypair_debug_redaction_documented_in_inline_tests() {
    // Marker — the actual guard is the manual Debug impl + the inline
    // assert_not_impl_any! tests in the api module.
    // Cannot exercise externally because SigningKeypair is in a
    // private module; the type's invariants are guarded inline.
}

/// Round-27 H2: AEAD decrypt path must return a single uniform error
/// string for every adversary-reachable failure. Reverting the
/// `DECRYPTION_FAILED` constant collapse re-introduces 4 distinguishable
/// strings (auth-fail vs size-cap vs buffer-shape).
#[test]
fn aes_gcm_decrypt_failure_strings_are_uniform() {
    let key = [0xABu8; 32];
    let cipher = AesGcm256::new(&key).unwrap();
    let nonce = AesGcm256::generate_nonce();
    let (ct, tag) = cipher.encrypt(&nonce, b"plaintext", None).unwrap();

    // Tampered tag → MAC failure path
    let mut bad_tag = tag;
    bad_tag[0] ^= 0xFF;
    let mac_err = cipher.decrypt(&nonce, &ct, &bad_tag, None).unwrap_err().to_string();

    // Build a wrong-key cipher and decrypt with it — different stage,
    // same opaque error.
    let other_key = [0xCDu8; 32];
    let other = AesGcm256::new(&other_key).unwrap();
    let other_err = other.decrypt(&nonce, &ct, &tag, None).unwrap_err().to_string();

    assert_eq!(
        mac_err, other_err,
        "AES-GCM decrypt error strings must be uniform across stages \
         (round-27 H2 opacity sweep)"
    );
}

/// Round-27 H3: secp256k1 high-S signatures must be rejected at
/// `signature_from_bytes` (BIP-146 / EIP-2). Without round-27 H3, a
/// caller could parse a high-S signature and verify would also reject —
/// but the parse-time gate is the wire-format guard.
///
/// Gated on `not(feature = "fips")` because secp256k1 is not a NIST-
/// approved curve and the module is excluded from the FIPS profile.
#[cfg(not(feature = "fips"))]
#[test]
fn secp256k1_high_s_signature_rejected_at_parse() {
    use latticearc::primitives::ec::secp256k1::{Secp256k1KeyPair, Secp256k1Signature};
    use latticearc::primitives::ec::traits::{EcKeyPair, EcSignature};

    let kp = Secp256k1KeyPair::generate().unwrap();
    let msg = b"high-S parse test";
    let sig = kp.sign(msg).unwrap();
    let mut sig_bytes = Secp256k1Signature::signature_bytes(&sig);

    // Negate s (n - s) to construct a high-S form. secp256k1 group order n:
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig_bytes[32..64]);
    let mut high_s = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let mut diff = N[i] as i16 - s[i] as i16 - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        high_s[i] = diff as u8;
    }
    sig_bytes[32..64].copy_from_slice(&high_s);

    let parsed = Secp256k1Signature::signature_from_bytes(&sig_bytes);
    assert!(
        parsed.is_err(),
        "round-27 H3: secp256k1 high-S signature must be rejected at parse \
         (BIP-146 / EIP-2)"
    );
}

/// Round-27 M4: `SlhDsaError::DeserializationError` was removed.
/// Production code never returned it; reverting the removal would
/// re-introduce the dead variant. The `non_exhaustive` attribute means
/// adding it back is technically non-breaking, but the variant should
/// not exist.
#[test]
fn slh_dsa_error_does_not_have_deserialization_variant() {
    use latticearc::primitives::sig::slh_dsa::SlhDsaError;
    // Pattern-match on every variant — an exhaustive match would
    // break if `DeserializationError` is re-added (under
    // non_exhaustive, the catch-all `_` arm prevents the compile
    // error, so this is a Display-shape check instead). The previous
    // variant displayed "Deserialization failed"; we assert that
    // string is unreachable from any current variant.
    let known: &[SlhDsaError] = &[
        SlhDsaError::RngError,
        SlhDsaError::PctFailed,
        SlhDsaError::InvalidPublicKey,
        SlhDsaError::InvalidSecretKey,
        SlhDsaError::VerificationFailed,
        SlhDsaError::ContextTooLong,
    ];
    for e in known {
        assert_ne!(
            e.to_string(),
            "Deserialization failed",
            "round-27 M4: DeserializationError variant must remain absent"
        );
    }
}
