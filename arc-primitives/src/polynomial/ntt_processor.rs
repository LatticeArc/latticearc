#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: NTT (Number Theoretic Transform) is finite-field arithmetic.
// - Array indexing is bounded by power-of-2 constraints (verified at construction)
// - Arithmetic is modular and cannot overflow
// - Performance-critical for lattice-based cryptography (ML-KEM, ML-DSA)
// - Sizes bounded to small values (256, 512, 1024) by find_primitive_root
// - Result<> used for API consistency across functions
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unnecessary_wraps)]

use crate::polynomial::arithmetic::{mod_inverse, mod_pow};
use arc_prelude::error::{LatticeArcError, Result};

/// NTT processor for fast polynomial operations
pub struct NttProcessor {
    /// Precomputed twiddle factors for forward NTT
    forward_twiddles: Vec<i32>,
    /// Precomputed twiddle factors for inverse NTT
    inverse_twiddles: Vec<i32>,
    /// NTT size (must be power of 2)
    pub(crate) n: usize,
    /// Modulus for arithmetic
    pub(crate) modulus: i64,
    /// Primitive NTT root of unity
    primitive_root: i32,
}

impl NttProcessor {
    /// Get precomputed forward NTT twiddle factors
    #[must_use]
    pub fn forward_twiddles(&self) -> &[i32] {
        &self.forward_twiddles
    }

    /// Get precomputed inverse NTT twiddle factors
    #[must_use]
    pub fn inverse_twiddles(&self) -> &[i32] {
        &self.inverse_twiddles
    }
    /// Find primitive Nth root of unity modulo modulus
    ///
    /// Uses precomputed roots for known parameter sets (Kyber, Dilithium).
    /// For other parameters, returns an error as finding primitive roots
    /// modulo arbitrary moduli is computationally expensive.
    fn find_primitive_root(n: usize, modulus: i64) -> Result<i32> {
        match (n, modulus) {
            (256, 3329) => Ok(17),   // Kyber parameters
            (512, 12289) => Ok(49),  // Dilithium parameters
            (1024, 12289) => Ok(49), // Dilithium parameters
            _ => Err(LatticeArcError::InvalidInput(format!(
                "No known primitive root for N={}, modulus={}",
                n, modulus
            ))),
        }
    }

    /// Compute forward NTT twiddle factors
    fn compute_twiddles(n: usize, primitive_root: i32, modulus: i64) -> Result<Vec<i32>> {
        let mut twiddles = vec![0i32; n];
        let root_pow = mod_pow(i64::from(primitive_root), (modulus - 1) / n as i64, modulus);

        twiddles[0] = 1;
        for (i, twiddle) in twiddles.iter_mut().enumerate().skip(1).take(n - 1) {
            *twiddle = mod_pow(root_pow, i as i64, modulus) as i32;
        }

        Ok(twiddles)
    }

    /// Compute inverse NTT twiddle factors
    fn compute_inverse_twiddles(n: usize, primitive_root: i32, modulus: i64) -> Result<Vec<i32>> {
        let mut twiddles = vec![0i32; n];
        let root_pow = mod_pow(i64::from(primitive_root), (modulus - 1) / n as i64, modulus);
        let inv_root_pow = mod_inverse(root_pow, modulus)?;

        twiddles[0] = 1;
        for (i, twiddle) in twiddles.iter_mut().enumerate().skip(1).take(n - 1) {
            *twiddle = mod_pow(inv_root_pow, i as i64, modulus) as i32;
        }

        Ok(twiddles)
    }

    /// Create new NTT processor for given size and modulus
    ///
    /// # Errors
    /// Returns an error if n is not a power of 2, modulus is invalid, or no primitive root is known.
    pub fn new(n: usize, modulus: i64) -> Result<Self> {
        if !n.is_power_of_two() {
            return Err(LatticeArcError::InvalidInput("NTT size must be a power of 2".to_string()));
        }

        if modulus <= 1 {
            return Err(LatticeArcError::InvalidInput(
                "Modulus must be greater than 1".to_string(),
            ));
        }

        // Find primitive NTT root of unity
        let primitive_root = Self::find_primitive_root(n, modulus)?;

        // Precompute twiddle factors
        let forward_twiddles = Self::compute_twiddles(n, primitive_root, modulus)?;
        let inverse_twiddles = Self::compute_inverse_twiddles(n, primitive_root, modulus)?;

        Ok(Self { forward_twiddles, inverse_twiddles, n, modulus, primitive_root })
    }

    /// Forward NTT transform (coefficient to evaluation domain)
    ///
    /// # Errors
    /// Returns an error if input length does not match NTT size.
    pub fn forward(&self, coeffs: &[i32]) -> Result<Vec<i32>> {
        if coeffs.len() != self.n {
            return Err(LatticeArcError::InvalidInput(format!(
                "Input length {} doesn't match NTT size {}",
                coeffs.len(),
                self.n
            )));
        }

        let mut result = coeffs.to_vec();
        self.ntt(&mut result, false)?;
        Ok(result)
    }

    /// Inverse NTT transform (evaluation to coefficient domain)
    ///
    /// # Errors
    /// Returns an error if input length does not match NTT size.
    pub fn inverse(&self, evaluations: &[i32]) -> Result<Vec<i32>> {
        if evaluations.len() != self.n {
            return Err(LatticeArcError::InvalidInput(format!(
                "Input length {} doesn't match NTT size {}",
                evaluations.len(),
                self.n
            )));
        }

        let mut result = evaluations.to_vec();
        self.ntt(&mut result, true)?;

        // Scale by inverse of n
        // n is bounded to small values (256, 512, 1024) by find_primitive_root
        let n_i64 = i64::try_from(self.n).map_err(|_e| {
            LatticeArcError::InvalidInput("NTT size exceeds i64 range".to_string())
        })?;
        let n_inv_i64 = mod_inverse(n_i64, self.modulus)?;
        let n_inv = i32::try_from(n_inv_i64).map_err(|_e| {
            LatticeArcError::InvalidInput("NTT inverse exceeds i32 range".to_string())
        })?;
        for coeff in &mut result {
            *coeff = self.mod_mul(*coeff, n_inv);
        }

        Ok(result)
    }

    /// Fast polynomial multiplication using NTT
    ///
    /// # Errors
    /// Returns an error if polynomial lengths do not match NTT size.
    pub fn multiply(&self, a: &[i32], b: &[i32]) -> Result<Vec<i32>> {
        if a.len() != self.n || b.len() != self.n {
            return Err(LatticeArcError::InvalidInput(
                "Polynomial lengths must match NTT size".to_string(),
            ));
        }

        // Transform to evaluation domain
        let a_eval = self.forward(a)?;
        let b_eval = self.forward(b)?;

        // Pointwise multiplication
        let mut c_eval = vec![0i32; self.n];
        for i in 0..self.n {
            if let (Some(&a_val), Some(&b_val)) = (a_eval.get(i), b_eval.get(i))
                && let Some(c_val) = c_eval.get_mut(i)
            {
                *c_val = self.mod_mul(a_val, b_val);
            }
        }

        // Transform back to coefficient domain
        self.inverse(&c_eval)
    }

    /// Modular multiplication
    fn mod_mul(&self, a: i32, b: i32) -> i32 {
        ((i64::from(a) * i64::from(b)) % self.modulus) as i32
    }

    /// Modular addition
    fn mod_add(&self, a: i32, b: i32) -> i32 {
        let sum = i64::from(a) + i64::from(b);
        (sum % self.modulus) as i32
    }

    /// Modular subtraction
    fn mod_sub(&self, a: i32, b: i32) -> i32 {
        let diff = i64::from(a) - i64::from(b);
        let result = diff % self.modulus;
        if result < 0 { (result + self.modulus) as i32 } else { result as i32 }
    }

    /// Core NTT implementation (Cooley-Tukey FFT-like algorithm)
    fn ntt(&self, data: &mut [i32], inverse: bool) -> Result<()> {
        let n = data.len();

        // Bit-reversal permutation
        let mut j = 0;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;

            if i < j {
                data.swap(i, j);
            }
        }

        // Iterative Cooley-Tukey NTT
        //
        // The algorithm performs butterfly operations at each level:
        //     u -----> + -----> u'
        //              |
        //              | * w
        //              |
        //     v -----> - -----> v'
        //
        // Where u' = u + w*v, v' = u - w*v (mod modulus)
        let root = if inverse {
            let inv = mod_inverse(i64::from(self.primitive_root), self.modulus)?;
            i32::try_from(inv).map_err(|_e| {
                LatticeArcError::InvalidInput("Root inverse exceeds i32 range".to_string())
            })?
        } else {
            self.primitive_root
        };

        let mut length = 2;
        while length <= n {
            let length_i64 = i64::try_from(length).map_err(|_e| {
                LatticeArcError::InvalidInput("NTT length exceeds i64 range".to_string())
            })?;
            let wlen_i64 = mod_pow(i64::from(root), (self.modulus - 1) / length_i64, self.modulus);
            let wlen = i32::try_from(wlen_i64).map_err(|_e| {
                LatticeArcError::InvalidInput("Twiddle factor exceeds i32 range".to_string())
            })?;
            let mut i = 0;
            while i < n {
                let mut w = 1;
                let half_len = length / 2;

                // Split the current block [i..i+length] into two halves:
                // u_slice: [i..i+half_len]
                // v_slice: [i+half_len..i+length]
                let (left, right) = data.split_at_mut(i + half_len);
                let u_slice = &mut left[i..];
                let v_slice = &mut right[..half_len];

                for j in 0..half_len {
                    if let (Some(&u), Some(&v_data)) = (u_slice.get(j), v_slice.get(j)) {
                        let v = self.mod_mul(v_data, w);
                        u_slice[j] = self.mod_add(u, v);
                        v_slice[j] = self.mod_sub(u, v);
                    }
                    w = self.mod_mul(w, wlen);
                }
                i += length;
            }
            length *= 2;
        }
        Ok(())
    }

    /// Scalar NTT implementation using precomputed twiddle factors
    ///
    /// This is a low-level method for custom NTT implementations.
    /// For standard use, prefer `forward()` and `inverse()`.
    #[inline]
    pub fn ntt_scalar(
        &self,
        data: &mut [i32],
        twiddles: &[i32],
        size: usize,
        half_size: usize,
        step: usize,
    ) {
        for i in (0..data.len()).step_by(size) {
            let mut k = 0;
            let (first_half, second_half) = data.split_at_mut(i + size);
            let (first_part, _) = first_half.split_at_mut(i);
            let u_slice = &mut first_part[i..i + half_size];
            let v_slice = &mut second_half[..half_size];

            for j in 0..half_size {
                if let (Some(&u), Some(&v_data)) = (u_slice.get(j), v_slice.get(j))
                    && let Some(twiddle) = twiddles.get(k)
                {
                    let v = self.mod_mul(v_data, *twiddle);
                    u_slice[j] = self.mod_add(u, v);
                    v_slice[j] = self.mod_sub(u, v);
                }
                k += step;
            }
        }
    }
}
