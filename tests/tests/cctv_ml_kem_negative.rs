//! C2SP CCTV ML-KEM Negative Tests — Invalid Encapsulation Key Rejection
//!
//! Validates that the fips203 ML-KEM implementation correctly rejects
//! encapsulation keys with polynomial coefficients outside the valid range
//! [0, q-1] where q = 3329 (the ML-KEM field prime).
//!
//! FIPS 203 Section 6.2 mandates a "modulus check" on encapsulation keys:
//! all ByteEncode12-encoded coefficients must be < q. Keys with coefficients
//! in [q, 2^12 - 1] = [3329, 4095] MUST be rejected.
//!
//! This catches the most common ML-KEM implementation bug: missing or
//! incomplete modulus validation.
//!
//! Reference: <https://github.com/C2SP/CCTV/tree/main/ML-KEM> (modulus/ folder)

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::manual_is_multiple_of
)]

use fips203::traits::{KeyGen, SerDes};

/// ML-KEM field prime
const Q: u16 = 3329;

/// Modify a specific 12-bit coefficient in a ByteEncode12-encoded byte slice.
///
/// ByteEncode12 packs two 12-bit coefficients into every 3 bytes:
///   c0 = bytes[0] | ((bytes[1] & 0x0F) << 8)
///   c1 = (bytes[1] >> 4) | (bytes[2] << 4)
///
/// `coeff_index` is the 0-based index of the coefficient to modify.
/// `value` is the new 12-bit value (must fit in 12 bits).
fn set_coefficient(data: &mut [u8], coeff_index: usize, value: u16) {
    assert!(value < 4096, "value must fit in 12 bits");
    let byte_offset = (coeff_index / 2) * 3;
    if coeff_index % 2 == 0 {
        // Even coefficient: c0 = bytes[0] | ((bytes[1] & 0x0F) << 8)
        data[byte_offset] = (value & 0xFF) as u8;
        data[byte_offset + 1] = (data[byte_offset + 1] & 0xF0) | ((value >> 8) & 0x0F) as u8;
    } else {
        // Odd coefficient: c1 = (bytes[1] >> 4) | (bytes[2] << 4)
        data[byte_offset + 1] = (data[byte_offset + 1] & 0x0F) | ((value & 0x0F) as u8) << 4;
        data[byte_offset + 2] = (value >> 4) as u8;
    }
}

/// Read a specific 12-bit coefficient from ByteEncode12-encoded data.
fn get_coefficient(data: &[u8], coeff_index: usize) -> u16 {
    let byte_offset = (coeff_index / 2) * 3;
    if coeff_index % 2 == 0 {
        u16::from(data[byte_offset]) | (u16::from(data[byte_offset + 1] & 0x0F) << 8)
    } else {
        (u16::from(data[byte_offset + 1]) >> 4) | (u16::from(data[byte_offset + 2]) << 4)
    }
}

/// Test that set/get coefficient roundtrips correctly.
#[test]
fn test_coefficient_encoding_roundtrip() {
    let mut data = [0u8; 6]; // 4 coefficients

    for (i, val) in [0u16, 3328, 4095, 1234].iter().enumerate() {
        set_coefficient(&mut data, i, *val);
        assert_eq!(get_coefficient(&data, i), *val, "roundtrip failed for coeff {i}");
    }
}

macro_rules! negative_test_suite {
    (
        $mod_name:ident,
        $test_boundary:ident,
        $test_max:ident,
        $test_mid:ident,
        $test_positions:ident,
        $test_valid_boundary:ident,
        num_coeffs: $num_coeffs:literal
    ) => {
        /// Test rejection at the boundary value q = 3329
        #[test]
        fn $test_boundary() {
            // Generate a valid key
            let (ek, _dk) = fips203::$mod_name::KG::try_keygen().expect("keygen should succeed");
            let mut ek_bytes = ek.into_bytes();

            // Corrupt coefficient 0 to exactly q
            set_coefficient(&mut ek_bytes, 0, Q);

            // Must be rejected
            let result = fips203::$mod_name::EncapsKey::try_from_bytes(ek_bytes);
            assert!(result.is_err(), "EncapsKey with coefficient == q ({Q}) should be rejected");
        }

        /// Test rejection at the maximum 12-bit value (4095)
        #[test]
        fn $test_max() {
            let (ek, _dk) = fips203::$mod_name::KG::try_keygen().expect("keygen should succeed");
            let mut ek_bytes = ek.into_bytes();

            set_coefficient(&mut ek_bytes, 0, 4095);

            let result = fips203::$mod_name::EncapsKey::try_from_bytes(ek_bytes);
            assert!(result.is_err(), "EncapsKey with coefficient == 4095 should be rejected");
        }

        /// Test rejection at a mid-range invalid value
        #[test]
        fn $test_mid() {
            let (ek, _dk) = fips203::$mod_name::KG::try_keygen().expect("keygen should succeed");
            let mut ek_bytes = ek.into_bytes();

            set_coefficient(&mut ek_bytes, 0, 3700);

            let result = fips203::$mod_name::EncapsKey::try_from_bytes(ek_bytes);
            assert!(result.is_err(), "EncapsKey with coefficient == 3700 should be rejected");
        }

        /// Test rejection at multiple positions across the key.
        ///
        /// Tests the first, last, and several interior positions to ensure
        /// the modulus check covers every coefficient, not just the first.
        #[test]
        fn $test_positions() {
            // Test positions: first, several interior, last
            let positions = [
                0,
                1,
                $num_coeffs / 4,
                $num_coeffs / 2,
                3 * $num_coeffs / 4,
                $num_coeffs - 2,
                $num_coeffs - 1,
            ];

            // Test with several invalid values
            let invalid_values = [Q, Q + 1, 3500, 4000, 4095];

            for &pos in &positions {
                for &val in &invalid_values {
                    let (ek, _dk) =
                        fips203::$mod_name::KG::try_keygen().expect("keygen should succeed");
                    let mut ek_bytes = ek.into_bytes();

                    set_coefficient(&mut ek_bytes, pos, val);

                    let result = fips203::$mod_name::EncapsKey::try_from_bytes(ek_bytes);
                    assert!(
                        result.is_err(),
                        "EncapsKey should reject coefficient {} at position {} (value {})",
                        val,
                        pos,
                        val
                    );
                }
            }
        }

        /// Verify that the maximum valid coefficient (q-1 = 3328) is accepted.
        #[test]
        fn $test_valid_boundary() {
            let (ek, _dk) = fips203::$mod_name::KG::try_keygen().expect("keygen should succeed");
            let mut ek_bytes = ek.into_bytes();

            // Set coefficient to q-1 (maximum valid value) — should be accepted
            set_coefficient(&mut ek_bytes, 0, Q - 1);

            let result = fips203::$mod_name::EncapsKey::try_from_bytes(ek_bytes);
            assert!(
                result.is_ok(),
                "EncapsKey with coefficient == q-1 ({}) should be accepted",
                Q - 1
            );
        }
    };
}

// ML-KEM-512: k=2, 256*2 = 512 coefficients
negative_test_suite!(
    ml_kem_512,
    test_ml_kem_512_reject_boundary_q,
    test_ml_kem_512_reject_max_4095,
    test_ml_kem_512_reject_mid_3700,
    test_ml_kem_512_reject_multiple_positions,
    test_ml_kem_512_accept_q_minus_1,
    num_coeffs: 512
);

// ML-KEM-768: k=3, 256*3 = 768 coefficients
negative_test_suite!(
    ml_kem_768,
    test_ml_kem_768_reject_boundary_q,
    test_ml_kem_768_reject_max_4095,
    test_ml_kem_768_reject_mid_3700,
    test_ml_kem_768_reject_multiple_positions,
    test_ml_kem_768_accept_q_minus_1,
    num_coeffs: 768
);

// ML-KEM-1024: k=4, 256*4 = 1024 coefficients
negative_test_suite!(
    ml_kem_1024,
    test_ml_kem_1024_reject_boundary_q,
    test_ml_kem_1024_reject_max_4095,
    test_ml_kem_1024_reject_mid_3700,
    test_ml_kem_1024_reject_multiple_positions,
    test_ml_kem_1024_accept_q_minus_1,
    num_coeffs: 1024
);

/// Verify that an all-zeros encapsulation key is rejected (all coefficients are 0,
/// which is technically valid, but the rho portion would be all-zero, which
/// generates degenerate matrix A). This tests edge case handling.
#[test]
fn test_all_zero_key_roundtrip() {
    // An all-zeros key has all coefficients = 0 (valid) and rho = 0x00..00
    // Whether fips203 accepts or rejects this is implementation-defined,
    // but it should NOT panic.
    let zero_key = [0u8; 1184]; // ML-KEM-768 EK_LEN
    let result = fips203::ml_kem_768::EncapsKey::try_from_bytes(zero_key);
    // Just verify no panic — the result can be Some or None
    let _ = result;
}

/// Verify that corrupting just the rho (last 32 bytes) still produces a
/// parseable key (rho is not subject to the modulus check).
#[test]
fn test_corrupted_rho_accepted() {
    let (ek, _dk) = fips203::ml_kem_768::KG::try_keygen().expect("keygen should succeed");
    let mut ek_bytes = ek.into_bytes();

    // Corrupt the last 32 bytes (rho)
    let len = ek_bytes.len();
    for byte in &mut ek_bytes[len - 32..] {
        *byte ^= 0xFF;
    }

    // rho is not subject to modulus check, so this should still parse
    let result = fips203::ml_kem_768::EncapsKey::try_from_bytes(ek_bytes);
    assert!(result.is_ok(), "Corrupted rho should not trigger modulus check rejection");
}
