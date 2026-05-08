#![allow(clippy::expect_used)]

//! ML-DSA KAT integration tests
//!
//! Runs the deterministic keygen regression tests and sign/verify roundtrip
//! verification for all three ML-DSA parameter sets (44, 65, 87).

use latticearc_tests::validation::nist_kat::ml_dsa_kat;

// ============================================================================
// Keygen Fingerprint Tests
// ============================================================================

#[test]
fn test_ml_dsa_44_keygen_fingerprint_matches_recorded() {
    let fp = &ml_dsa_kat::ML_DSA_44_FINGERPRINT;
    assert_eq!(fp.test_name, "ML-DSA-44-Keygen-Seed-Zeros");
    assert_eq!(fp.pk_len, 1312);
}

#[test]
fn test_ml_dsa_65_keygen_fingerprint_matches_recorded() {
    let fp = &ml_dsa_kat::ML_DSA_65_FINGERPRINT;
    assert_eq!(fp.test_name, "ML-DSA-65-Keygen-Seed-Zeros");
    assert_eq!(fp.pk_len, 1952);
}

#[test]
fn test_ml_dsa_87_keygen_fingerprint_matches_recorded() {
    let fp = &ml_dsa_kat::ML_DSA_87_FINGERPRINT;
    assert_eq!(fp.test_name, "ML-DSA-87-Keygen-Seed-Zeros");
    assert_eq!(fp.pk_len, 2592);
}

// ============================================================================
// Full KAT Runner Tests (keygen regression + sign/verify roundtrip)
// ============================================================================

#[test]
fn test_ml_dsa_44_kat_passes() {
    ml_dsa_kat::run_ml_dsa_44_kat().expect("ML-DSA-44 KAT should pass");
}

#[test]
fn test_ml_dsa_65_kat_passes() {
    ml_dsa_kat::run_ml_dsa_65_kat().expect("ML-DSA-65 KAT should pass");
}

#[test]
fn test_ml_dsa_87_kat_passes() {
    ml_dsa_kat::run_ml_dsa_87_kat().expect("ML-DSA-87 KAT should pass");
}

// ============================================================================
// Fingerprint format validation
// ============================================================================

#[test]
fn test_ml_dsa_fingerprints_are_valid_hex() {
    use latticearc_tests::validation::nist_kat::decode_hex;

    let fps = [
        &ml_dsa_kat::ML_DSA_44_FINGERPRINT,
        &ml_dsa_kat::ML_DSA_65_FINGERPRINT,
        &ml_dsa_kat::ML_DSA_87_FINGERPRINT,
    ];
    for fp in fps {
        let pk_bytes = decode_hex(fp.pk_first32).expect("pk_first32 should be valid hex");
        assert_eq!(pk_bytes.len(), 32, "pk_first32 should decode to 32 bytes");
    }
}
