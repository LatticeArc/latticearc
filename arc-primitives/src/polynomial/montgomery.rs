#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Montgomery reduction is modular arithmetic over finite fields.
// All operations are mathematically bounded by the modulus (cannot overflow).
// These operations are performance-critical for lattice cryptography.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]

use crate::polynomial::arithmetic::mod_inverse;
use arc_prelude::error::{LatticeArcError, Result};

/// Montgomery reduction for efficient modular arithmetic
pub struct MontgomeryReducer {
    modulus: i64,
    r: i64,       // R = 2^32 for 32-bit modulus
    r_inv: i64,   // R^{-1} mod modulus
    n_prime: i64, // -modulus^{-1} mod R
}

impl MontgomeryReducer {
    /// Get R^{-1} mod modulus (useful for alternative conversion methods)
    #[must_use]
    pub fn r_inv(&self) -> i64 {
        self.r_inv
    }

    /// Create new Montgomery reducer for given modulus.
    ///
    /// # Errors
    /// Returns an error if the modulus is not positive or if modular inverse computation fails.
    pub fn new(modulus: i64) -> Result<Self> {
        if modulus <= 0 {
            return Err(LatticeArcError::InvalidInput("Modulus must be positive".to_string()));
        }

        let r = 1i64 << 32; // 2^32
        let r_inv = mod_inverse(r % modulus, modulus)?;
        let n_prime = mod_inverse(modulus, r)?;
        let n_prime = (r - n_prime) % r;

        Ok(Self { modulus, r, r_inv, n_prime })
    }

    /// Convert to Montgomery form
    #[must_use]
    pub fn to_montgomery(&self, x: i64) -> i64 {
        let x_wide = i128::from(x);
        let r_wide = i128::from(self.r);
        let modulus_wide = i128::from(self.modulus);
        ((x_wide * r_wide) % modulus_wide) as i64
    }

    /// Convert from Montgomery form
    #[must_use]
    pub fn from_montgomery(&self, x: i64) -> i64 {
        let x_wide = i128::from(x);
        let n_prime_wide = i128::from(self.n_prime);
        let r_wide = i128::from(self.r);
        let modulus_wide = i128::from(self.modulus);

        let u = ((x_wide * n_prime_wide) % r_wide) as i64;
        let u_wide = i128::from(u);
        let result = ((x_wide + u_wide * modulus_wide) / r_wide) as i64;
        result % self.modulus
    }

    /// Montgomery multiplication
    #[must_use]
    pub fn multiply(&self, a: i64, b: i64) -> i64 {
        let a_wide = i128::from(a);
        let b_wide = i128::from(b);
        let t = a_wide * b_wide;

        let n_prime_wide = i128::from(self.n_prime);
        let r_wide = i128::from(self.r);
        let u = ((t * n_prime_wide) % r_wide) as i64;

        let u_wide = i128::from(u);
        let modulus_wide = i128::from(self.modulus);
        let result = (t + u_wide * modulus_wide) / r_wide;
        (result as i64) % self.modulus
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduction() -> Result<()> {
        // Use a prime modulus suitable for Montgomery reduction
        let modulus = 12289i64; // A common NTT prime
        let reducer = MontgomeryReducer::new(modulus)?;

        let a = 12345i64 % modulus;
        let b = 67890i64 % modulus;

        let mont_a = reducer.to_montgomery(a);
        let mont_b = reducer.to_montgomery(b);
        let mont_result = reducer.multiply(mont_a, mont_b);
        let result = reducer.from_montgomery(mont_result);

        let expected = (a * b) % modulus;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_montgomery_reducer_zero_modulus() {
        let result = MontgomeryReducer::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_montgomery_reducer_negative_modulus() {
        let result = MontgomeryReducer::new(-1);
        assert!(result.is_err());
    }

    #[test]
    fn test_montgomery_identity_operations() -> Result<()> {
        let modulus = 12289i64;
        let reducer = MontgomeryReducer::new(modulus)?;

        let a = 42i64;
        let mont_a = reducer.to_montgomery(a);
        let back = reducer.from_montgomery(mont_a);

        assert_eq!(back, a % modulus);
        Ok(())
    }

    #[test]
    fn test_montgomery_multiplication_by_one() -> Result<()> {
        let modulus = 12289i64;
        let reducer = MontgomeryReducer::new(modulus)?;

        let a = 12345i64 % modulus;
        let a_mont = reducer.to_montgomery(a);
        let one_mont = reducer.to_montgomery(1);

        let result_mont = reducer.multiply(a_mont, one_mont);
        let result = reducer.from_montgomery(result_mont);

        assert_eq!(result, a);
        Ok(())
    }
}
