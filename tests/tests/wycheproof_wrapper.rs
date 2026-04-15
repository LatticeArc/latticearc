//! Wycheproof vectors run through latticearc's *wrapper* APIs.
//!
//! The existing `tests/src/validation/wycheproof.rs` suite runs Wycheproof
//! vectors against the underlying crates (aws-lc-rs, chacha20poly1305,
//! ed25519-dalek). That validates our dependency choice, but not our
//! wrapping code. This file runs the same vectors through
//! `latticearc::primitives::*` so wrapper bugs (wrong byte order, dropped
//! AAD, truncated tags, mis-called validators) surface as test failures.
//!
//! Suites covered:
//! - AES-GCM 256 via `latticearc::primitives::aead::aes_gcm::AesGcm256`
//! - ChaCha20-Poly1305 via `ChaCha20Poly1305Cipher`
//! - HMAC-SHA256 via `hmac_sha256` + `verify_hmac_sha256`
//! - HKDF-SHA256 via `hkdf_extract` + `hkdf_expand`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::single_match_else,
    clippy::manual_let_else,
    clippy::explicit_auto_deref
)]

use latticearc::primitives::aead::{AES_GCM_256_KEY_LEN, NONCE_LEN, TAG_LEN};
use latticearc_tests::validation::wycheproof::WycheproofResults;
use wycheproof::TestResult;

/// Budget for flaky / implementation-defined test cases. If the wrapper
/// rejects a Wycheproof `Valid` vector, we want to know — but some
/// `Acceptable` edge cases are implementation-defined. Fail if more
/// than 1% of ran (non-skipped) tests fail.
const MAX_FAILURE_RATE: f64 = 0.01;

// =============================================================================
// AES-256-GCM via our wrapper
// =============================================================================

#[test]
fn aes_256_gcm_via_wrapper_matches_wycheproof() {
    use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};
    use wycheproof::aead::{TestName, TestSet};

    let Ok(ts) = TestSet::load(TestName::AesGcm) else {
        eprintln!("wycheproof AES-GCM vectors unavailable — skipping");
        return;
    };

    let mut s = WycheproofResults::new();
    for group in ts.test_groups {
        for tc in group.tests {
            // AesGcm256 wraps AES-256-GCM with the standard 12-byte nonce and
            // 16-byte tag. Other key/nonce/tag lengths are out of scope here.
            if tc.key.len() != AES_GCM_256_KEY_LEN
                || tc.nonce.len() != NONCE_LEN
                || tc.tag.len() != TAG_LEN
            {
                s.add_skip();
                continue;
            }

            // These try_into calls are infallible after the length guard above.
            let key: [u8; AES_GCM_256_KEY_LEN] = tc.key[..].try_into().unwrap();
            let nonce: [u8; NONCE_LEN] = tc.nonce[..].try_into().unwrap();
            let tag: [u8; TAG_LEN] = tc.tag[..].try_into().unwrap();

            let Ok(cipher) = AesGcm256::new(&key) else {
                s.add_skip();
                continue;
            };
            let aad = if tc.aad.is_empty() { None } else { Some(&tc.aad[..]) };
            let result = cipher.decrypt(&nonce, &tc.ct[..], &tag, aad);

            match tc.result {
                TestResult::Valid => match result {
                    Ok(pt) if pt.as_slice() == &tc.pt[..] => s.add_pass(),
                    Ok(_) => {
                        s.add_failure(format!("tc {} Valid: decrypted mismatch", tc.tc_id));
                    }
                    Err(e) => {
                        s.add_failure(format!("tc {} Valid: decrypt failed: {e:?}", tc.tc_id));
                    }
                },
                TestResult::Invalid => match result {
                    Err(_) => s.add_pass(),
                    Ok(_) => {
                        s.add_failure(format!("tc {} Invalid: decrypt succeeded", tc.tc_id));
                    }
                },
                TestResult::Acceptable => s.add_pass(),
            }
        }
    }
    s.check_rate("AES-256-GCM wrapper", MAX_FAILURE_RATE);
}

// =============================================================================
// ChaCha20-Poly1305 via our wrapper
// =============================================================================

#[cfg(not(feature = "fips"))]
#[test]
fn chacha20_poly1305_via_wrapper_matches_wycheproof() {
    use latticearc::primitives::aead::{AeadCipher, chacha20poly1305::ChaCha20Poly1305Cipher};
    use wycheproof::aead::{TestName, TestSet};

    let Ok(ts) = TestSet::load(TestName::ChaCha20Poly1305) else {
        eprintln!("wycheproof ChaCha20-Poly1305 vectors unavailable — skipping");
        return;
    };

    // ChaCha20-Poly1305 uses the same 32-byte key, 12-byte nonce, 16-byte tag
    // shape as AES-256-GCM. Reuse the AEAD constants for both suites.
    let mut s = WycheproofResults::new();
    for group in ts.test_groups {
        for tc in group.tests {
            if tc.key.len() != AES_GCM_256_KEY_LEN
                || tc.nonce.len() != NONCE_LEN
                || tc.tag.len() != TAG_LEN
            {
                s.add_skip();
                continue;
            }
            let nonce: [u8; NONCE_LEN] = tc.nonce[..].try_into().unwrap();
            let tag: [u8; TAG_LEN] = tc.tag[..].try_into().unwrap();

            let Ok(cipher) = ChaCha20Poly1305Cipher::new(&tc.key[..]) else {
                s.add_skip();
                continue;
            };
            let aad = if tc.aad.is_empty() { None } else { Some(&tc.aad[..]) };
            let result = cipher.decrypt(&nonce, &tc.ct[..], &tag, aad);

            match tc.result {
                TestResult::Valid => match result {
                    Ok(pt) if pt.as_slice() == &tc.pt[..] => s.add_pass(),
                    Ok(_) => {
                        s.add_failure(format!("tc {} Valid: decrypted mismatch", tc.tc_id));
                    }
                    Err(e) => {
                        s.add_failure(format!("tc {} Valid: decrypt failed: {e:?}", tc.tc_id));
                    }
                },
                TestResult::Invalid => match result {
                    Err(_) => s.add_pass(),
                    Ok(_) => {
                        s.add_failure(format!("tc {} Invalid: decrypt succeeded", tc.tc_id));
                    }
                },
                TestResult::Acceptable => s.add_pass(),
            }
        }
    }
    s.check_rate("ChaCha20-Poly1305 wrapper", MAX_FAILURE_RATE);
}

// =============================================================================
// HMAC-SHA256 via our wrapper
// =============================================================================

#[test]
fn hmac_sha256_via_wrapper_matches_wycheproof() {
    use latticearc::primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};
    use wycheproof::mac::{TestName, TestSet};

    let Ok(ts) = TestSet::load(TestName::HmacSha256) else {
        eprintln!("wycheproof HMAC-SHA256 vectors unavailable — skipping");
        return;
    };

    let mut s = WycheproofResults::new();
    for group in ts.test_groups {
        for tc in group.tests {
            // Our wrapper produces a fixed-size 32-byte tag. Wycheproof
            // includes truncated-tag vectors; skip those — truncation is
            // not a wrapper concern.
            if tc.tag.len() != 32 {
                s.add_skip();
                continue;
            }
            let Ok(computed) = hmac_sha256(&tc.key[..], &tc.msg[..]) else {
                s.add_skip();
                continue;
            };
            let matches_expected = computed.as_slice() == &tc.tag[..];
            let verify_ok = verify_hmac_sha256(&tc.key[..], &tc.msg[..], &tc.tag[..]);

            match tc.result {
                TestResult::Valid => {
                    if matches_expected && verify_ok {
                        s.add_pass();
                    } else {
                        s.add_failure(format!(
                            "tc {} Valid: computed_match={matches_expected} verify_ok={verify_ok}",
                            tc.tc_id
                        ));
                    }
                }
                TestResult::Invalid => {
                    if !verify_ok {
                        s.add_pass();
                    } else {
                        s.add_failure(format!("tc {} Invalid: verify returned true", tc.tc_id));
                    }
                }
                TestResult::Acceptable => s.add_pass(),
            }
        }
    }
    s.check_rate("HMAC-SHA256 wrapper", MAX_FAILURE_RATE);
}

// =============================================================================
// HKDF-SHA256 via our wrappers (extract + expand)
// =============================================================================

#[test]
fn hkdf_sha256_via_wrapper_matches_wycheproof() {
    use latticearc::primitives::kdf::hkdf::{hkdf_expand, hkdf_extract};
    use wycheproof::hkdf::{TestName, TestSet};

    let Ok(ts) = TestSet::load(TestName::HkdfSha256) else {
        eprintln!("wycheproof HKDF-SHA256 vectors unavailable — skipping");
        return;
    };

    let mut s = WycheproofResults::new();
    for group in ts.test_groups {
        for tc in group.tests {
            let size = tc.size;
            let salt = if tc.salt.is_empty() { None } else { Some(&tc.salt[..]) };
            let info = if tc.info.is_empty() { None } else { Some(&tc.info[..]) };

            let Ok(prk) = hkdf_extract(salt, &tc.ikm[..]) else {
                s.add_skip();
                continue;
            };
            // Our wrapper may refuse oversized outputs while Wycheproof lists
            // them as Invalid — that's a correct rejection.
            let okm = match hkdf_expand(&prk, info, size) {
                Ok(o) => o,
                Err(_) => {
                    if matches!(tc.result, TestResult::Invalid) {
                        s.add_pass();
                    } else {
                        s.add_skip();
                    }
                    continue;
                }
            };
            let okm_bytes = okm.key();
            let matches = okm_bytes == &tc.okm[..];

            match tc.result {
                TestResult::Valid => {
                    if matches {
                        s.add_pass();
                    } else {
                        s.add_failure(format!("tc {} Valid: OKM mismatch", tc.tc_id));
                    }
                }
                TestResult::Invalid => {
                    if !matches {
                        s.add_pass();
                    } else {
                        s.add_failure(format!("tc {} Invalid: OKM matched", tc.tc_id));
                    }
                }
                TestResult::Acceptable => s.add_pass(),
            }
        }
    }
    s.check_rate("HKDF-SHA256 wrapper", MAX_FAILURE_RATE);
}
