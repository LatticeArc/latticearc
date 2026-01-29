#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Modular arithmetic over finite fields.
// All operations are bounded by the modulus (mathematically cannot overflow).
// Performance-critical for lattice cryptography primitives.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]

/// Modular exponentiation
#[must_use]
pub fn mod_pow(mut base: i64, mut exp: i64, modulus: i64) -> i64 {
    let mut result = 1i64;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            let base_wide = i128::from(base);
            let result_wide = i128::from(result);
            let modulus_wide = i128::from(modulus);
            result = ((result_wide * base_wide) % modulus_wide) as i64;
        }
        let base_wide = i128::from(base);
        let modulus_wide = i128::from(modulus);
        base = ((base_wide * base_wide) % modulus_wide) as i64;
        exp /= 2;
    }
    result
}

/// Modular inverse using extended Euclidean algorithm.
///
/// # Errors
/// Returns an error if the modular inverse does not exist (i.e., `a` and `m` are not coprime).
pub fn mod_inverse(a: i64, m: i64) -> arc_prelude::error::Result<i64> {
    let mut m0 = m;
    let mut y = 0i64;
    let mut x = 1i64;

    if m == 1 {
        return Ok(0);
    }

    let mut a = a;
    while a > 1 {
        let q = a / m0;
        let mut t = m0;
        m0 = a % m0;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if x < 0 {
        x += m;
    }

    if a > 1 {
        return Err(arc_prelude::error::LatticeArcError::InvalidInput(
            "Inverse doesn't exist".to_string(),
        ));
    }

    Ok(x)
}
