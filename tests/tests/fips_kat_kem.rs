#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

//! ML-KEM KAT integration tests
//!
//! Runs the deterministic keygen regression tests and encaps/decaps roundtrip
//! verification for all three ML-KEM parameter sets (512, 768, 1024).

use latticearc_tests::validation::nist_kat::ml_kem_kat;

// ============================================================================
// Keygen Fingerprint Tests
// ============================================================================

#[test]
fn test_ml_kem_512_keygen_fingerprint_matches_recorded() {
    let fp = &ml_kem_kat::ML_KEM_512_FINGERPRINTS[0];
    assert_eq!(fp.test_name, "ML-KEM-512-Keygen-Seed-Zeros");
    assert_eq!(fp.ek_len, 800);
    assert_eq!(fp.dk_len, 1632);
}

#[test]
fn test_ml_kem_768_keygen_fingerprint_matches_recorded() {
    let fp = &ml_kem_kat::ML_KEM_768_FINGERPRINTS[0];
    assert_eq!(fp.test_name, "ML-KEM-768-Keygen-Seed-Zeros");
    assert_eq!(fp.ek_len, 1184);
    assert_eq!(fp.dk_len, 2400);
}

#[test]
fn test_ml_kem_1024_keygen_fingerprint_matches_recorded() {
    let fp = &ml_kem_kat::ML_KEM_1024_FINGERPRINTS[0];
    assert_eq!(fp.test_name, "ML-KEM-1024-Keygen-Seed-Zeros");
    assert_eq!(fp.ek_len, 1568);
    assert_eq!(fp.dk_len, 3168);
}

// ============================================================================
// Full KAT Runner Tests (keygen regression + encaps/decaps roundtrip)
// ============================================================================

#[test]
fn test_ml_kem_512_kat_passes() {
    ml_kem_kat::run_ml_kem_512_kat().expect("ML-KEM-512 KAT should pass");
}

#[test]
fn test_ml_kem_768_kat_passes() {
    ml_kem_kat::run_ml_kem_768_kat().expect("ML-KEM-768 KAT should pass");
}

#[test]
fn test_ml_kem_1024_kat_passes() {
    ml_kem_kat::run_ml_kem_1024_kat().expect("ML-KEM-1024 KAT should pass");
}

// ============================================================================
// Fingerprint format validation
// ============================================================================

#[test]
fn test_ml_kem_fingerprints_are_valid_hex() {
    use latticearc_tests::validation::nist_kat::decode_hex;

    for fp in ml_kem_kat::ML_KEM_512_FINGERPRINTS {
        assert!(decode_hex(fp.ek_first32).is_ok(), "ek_first32 should be valid hex");
        assert!(decode_hex(fp.dk_first32).is_ok(), "dk_first32 should be valid hex");
        assert_eq!(decode_hex(fp.ek_first32).unwrap().len(), 32);
        assert_eq!(decode_hex(fp.dk_first32).unwrap().len(), 32);
    }
    for fp in ml_kem_kat::ML_KEM_768_FINGERPRINTS {
        assert_eq!(decode_hex(fp.ek_first32).unwrap().len(), 32);
        assert_eq!(decode_hex(fp.dk_first32).unwrap().len(), 32);
    }
    for fp in ml_kem_kat::ML_KEM_1024_FINGERPRINTS {
        assert_eq!(decode_hex(fp.ek_first32).unwrap().len(), 32);
        assert_eq!(decode_hex(fp.dk_first32).unwrap().len(), 32);
    }
}
