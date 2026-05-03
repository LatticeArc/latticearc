#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Modular arithmetic over finite fields.
// All operations are bounded by the modulus (mathematically cannot overflow).
// Performance-critical for lattice cryptography primitives.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]

/// Modular exponentiation.
///
/// Round-26 audit fix (L22): added a debug-assert precondition that
/// `modulus > 0`. The `i64` parameter type lets callers pass a
/// negative or zero modulus, which (a) panics on `base %= modulus`
/// when `modulus == 0`, and (b) produces undefined-by-convention
/// results when `modulus < 0`. The assertion is debug-only because
/// every internal caller (`ntt_processor::{find_primitive_root,
/// validate_primitive_root, compute_twiddles}`) supplies a positive
/// modulus from a known table; the assert exists to catch a future
/// callsite that forgets the precondition.
///
/// # Panics
/// In debug builds, panics if `modulus <= 0`.
#[must_use]
pub fn mod_pow(mut base: i64, mut exp: i64, modulus: i64) -> i64 {
    debug_assert!(modulus > 0, "mod_pow requires modulus > 0");
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
pub fn mod_inverse(a: i64, m: i64) -> crate::prelude::error::Result<i64> {
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

    // Round-26 audit fix (L21): tighten post-check to `a != 1`.
    // The previous `a > 1` check let `a == 0` (i.e. `gcd(input, m) == m`,
    // which means the inverse doesn't exist) slip through with `Ok(x)`,
    // returning garbage. `a == 1` is the unique correct termination
    // condition for the extended Euclidean algorithm; everything else
    // is an "inverse doesn't exist" error.
    if a != 1 {
        return Err(crate::prelude::error::LatticeArcError::InvalidInput(
            "Inverse doesn't exist".to_string(),
        ));
    }

    Ok(x)
}
