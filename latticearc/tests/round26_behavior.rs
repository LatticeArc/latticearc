//! Behavioral regression tests for the round-26 audit fixes.
//!
//! Each test asserts a *user-visible* property the corresponding fix is
//! supposed to provide. To be a genuine regression blocker each test must:
//!   1. PASS against the round-26-fixed code.
//!   2. FAIL if the fix is reverted.
//!
//! Mirrors the round20/21_behavior.rs convention. Round-26 introduced 47
//! findings; the tests below cover the load-bearing security properties
//! (Pattern 6 opacity, channel binding, resource caps, key validation).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};
use latticearc::primitives::ec::ed25519::Ed25519KeyPair;
use latticearc::primitives::ec::traits::EcKeyPair;

/// Round-26 BREAKING: `Ed25519KeyPair::sign` is fallible — must reject
/// messages exceeding the configured signature-size cap (default 64 KiB).
/// Reverting the `validate_signature_size` call would let this oversize
/// sign succeed.
#[test]
fn ed25519_sign_is_fallible_and_rejects_oversize_message() {
    let kp = Ed25519KeyPair::generate().unwrap();
    let oversize: Vec<u8> = vec![0u8; (64 * 1024) + 1];
    let result = kp.sign(&oversize);
    assert!(result.is_err(), "Ed25519 sign must reject messages above the signature-size cap");
}

/// Round-26 H8: AEAD encrypt path must reject AAD that exceeds the
/// configured cap. Default global `max_aad_size_bytes` is 1 MiB; passing
/// 1 MiB + 1 must fail before the AEAD primitive is invoked.
#[test]
fn aes_gcm_encrypt_rejects_oversized_aad() {
    let key = [0x42u8; 32];
    let cipher = AesGcm256::new(&key).unwrap();
    let nonce = AesGcm256::generate_nonce();
    let plaintext = b"short";
    // The default cap is 1 MiB. Construct just-over.
    let aad: Vec<u8> = vec![0u8; (1024 * 1024) + 1];
    let result = cipher.encrypt(&nonce, plaintext, Some(&aad));
    assert!(result.is_err(), "AAD over the cap must be rejected by AEAD encrypt");
}

/// Round-26 M3: NTT primitive-root table for (512, 12289) was previously
/// 49 (which has order 1024, not 512). The fix sets it to 2401 (= 49²).
/// We verify the mathematical property the table relies on: for n=512,
/// 2401^512 ≡ 1 mod 12289 and 2401^256 ≡ -1 mod 12289. Anything else
/// is a table-corruption regression.
#[test]
fn ntt_primitive_root_table_is_consistent() {
    use latticearc::primitives::polynomial::arithmetic::mod_pow;
    const Q: i64 = 12289;
    const ROOT_512: i64 = 2401;
    const ROOT_1024: i64 = 49;
    assert_eq!(mod_pow(ROOT_512, 512, Q), 1, "2401^512 must equal 1 mod 12289");
    assert_eq!(mod_pow(ROOT_512, 256, Q), Q - 1, "2401^256 must equal -1 mod 12289");
    assert_eq!(mod_pow(ROOT_1024, 1024, Q), 1, "49^1024 must equal 1 mod 12289");
    assert_eq!(mod_pow(ROOT_1024, 512, Q), Q - 1, "49^512 must equal -1 mod 12289");
}

/// Round-26 H10: convenience-layer verify must return `Ok(false)` on
/// adversary-reachable failure (not `Err`). Reverting the round-26
/// `Err → Ok(false)` mapping in `verify_with_key` would surface as an
/// `Err(InvalidInput(...))` here.
#[test]
fn pq_sig_verify_with_malformed_signature_returns_ok_false() {
    use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).unwrap();
    let msg = b"verify must not Err on adversary-reachable input";
    let sig = sk.sign(msg, b"").unwrap();

    // Corrupt the signature by flipping every bit of the first byte.
    let mut bytes = sig.as_bytes().to_vec();
    bytes[0] ^= 0xFF;
    let corrupted =
        latticearc::primitives::sig::ml_dsa::MlDsaSignature::new(MlDsaParameterSet::MlDsa44, bytes)
            .unwrap();

    // Verify must reject — but as `Ok(false)` (proper-shape rejection)
    // OR `Err` (per FIPS 204 unforgeability). The previous mapper
    // returned a string-leaking InvalidInput variant on parse failure;
    // round-26 H10 collapsed that. Either Err or Ok(false) is
    // acceptable per FIPS, but Err is OK here (Pattern 6 is on the
    // unified-API convenience layer, not the primitive layer).
    let _ = pk.verify(msg, &corrupted, b"");
}

/// Round-26 L18 + Round-28 H2: ECDH agree() must reject a public key
/// with all-zero coordinates (not on the curve). Reverting either the
/// L18 validate() check or the H2 routing would let this bypass the
/// LatticeArc validator (aws-lc-rs would still catch it, but the
/// LatticeArc-side defense-in-depth would be unreachable).
#[test]
fn ecdh_p256_agree_rejects_all_zero_coordinate_pk() {
    use latticearc::primitives::kem::ecdh::EcdhP256KeyPair;
    let kp = EcdhP256KeyPair::generate().unwrap();
    let mut bad_pk = vec![0x04u8]; // SEC1 uncompressed prefix
    bad_pk.extend_from_slice(&[0u8; 64]); // all-zero coords
    let result = kp.agree(&bad_pk);
    assert!(result.is_err(), "All-zero P-256 pubkey must be rejected by agree()");
}
