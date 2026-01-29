#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! CPU Implementation of Number Theoretic Transform for Cryptographic Operations
//!
//! Provides CPU-based implementations for NTT computations
//! in lattice-based cryptography, following NIST standards for polynomial arithmetic.

use arc_prelude::error::{LatticeArcError, Result};

/// CPU-based NTT processor for polynomial arithmetic in lattice cryptography
pub struct CpuNttProcessor {
    n: usize,
    q: i32,
}

impl CpuNttProcessor {
    /// Create new CPU NTT processor
    ///
    /// Initializes the processor with polynomial size n and modulus q,
    /// ensuring n is a power of 2 for efficient NTT computation.
    pub fn new(n: usize, q: i32) -> Result<Self> {
        if n & (n - 1) != 0 {
            return Err(LatticeArcError::InvalidInput(
                "NTT size must be a power of 2".to_string(),
            ));
        }
        if q <= 0 || q % 2 == 0 {
            return Err(LatticeArcError::InvalidInput(
                "Modulus q must be odd and positive".to_string(),
            ));
        }
        Ok(Self { n, q })
    }

    /// Forward NTT using Cooley-Tukey algorithm
    ///
    /// Performs forward Number Theoretic Transform on the input polynomial,
    /// transforming from coefficient representation to evaluation representation.
    /// Follows NIST guidelines for polynomial arithmetic in post-quantum cryptography.
    pub fn forward(&self, poly: &[i32]) -> Result<Vec<i32>> {
        if poly.len() != self.n {
            return Err(LatticeArcError::InvalidInput("Polynomial size mismatch".to_string()));
        }

        let mut result = poly.to_vec();
        self.ntt(&mut result, false);
        Ok(result)
    }

    /// Inverse NTT using Cooley-Tukey algorithm
    ///
    /// Performs inverse Number Theoretic Transform on the input polynomial,
    /// transforming from evaluation representation back to coefficient representation.
    /// Includes proper normalization by dividing by n.
    pub fn inverse(&self, poly: &[i32]) -> Result<Vec<i32>> {
        if poly.len() != self.n {
            return Err(LatticeArcError::InvalidInput("Polynomial size mismatch".to_string()));
        }

        let mut result = poly.to_vec();
        self.ntt(&mut result, true);
        Ok(result)
    }

    /// Complete NTT implementation using Cooley-Tukey algorithm
    /// Following NIST SP 800-185 for polynomial arithmetic in PQC
    fn ntt(&self, poly: &mut [i32], inverse: bool) {
        let n = self.n as usize;
        let q = self.q;

        // Bit reversal permutation
        let mut j = 0;
        for i in 1..n {
            let mut bit = n >> 1;
            while j >= bit {
                j -= bit;
                bit >>= 1;
            }
            j += bit;
            if i < j {
                poly.swap(i, j);
            }
        }

        // Cooley-Tukey iterative NTT
        let mut m = 1;
        while m < n {
            let omega_m = if inverse {
                self.mod_inverse(self.primitive_root(n), q)
            } else {
                self.primitive_root(n)
            };
            let mut k = 0;
            while k < n {
                let omega = self.mod_pow(omega_m, (n / (2 * m)) as i32, q);
                let mut w = 1;
                for j in 0..m {
                    let t = self.mod_mul(w, poly[k + j + m], q);
                    let u = poly[k + j];
                    poly[k + j] = self.mod_add(u, t, q);
                    poly[k + j + m] = self.mod_sub(u, t, q);
                    w = self.mod_mul(w, omega, q);
                }
                k += 2 * m;
            }
            m *= 2;
        }

        // For inverse NTT, divide by n
        if inverse {
            let n_inv = self.mod_inverse(n as i32, q);
            for i in 0..n {
                poly[i] = self.mod_mul(poly[i], n_inv, q);
            }
        }
    }

    fn primitive_root(&self, order: usize) -> i32 {
        let q = self.q;
        let phi = (q - 1) as usize;
        if phi % order != 0 {
            return 0; // No primitive root of that order
        }
        for g in 2..q {
            let mut is_primitive = true;
            for i in 1..order {
                if self.mod_pow(g, (phi / order * i) as i32, q) == 1 {
                    is_primitive = false;
                    break;
                }
            }
            if is_primitive {
                return g;
            }
        }
        0
    }

    fn mod_pow(&self, mut base: i32, mut exp: i32, mod_: i32) -> i32 {
        let mut result = 1;
        base %= mod_;
        while exp > 0 {
            if exp % 2 == 1 {
                result = self.mod_mul(result, base, mod_);
            }
            base = self.mod_mul(base, base, mod_);
            exp /= 2;
        }
        result
    }

    fn mod_add(&self, a: i32, b: i32, q: i32) -> i32 {
        ((a as i64 + b as i64) % q as i64) as i32
    }

    fn mod_sub(&self, a: i32, b: i32, q: i32) -> i32 {
        ((a as i64 - b as i64 + q as i64) % q as i64) as i32
    }

    fn mod_mul(&self, a: i32, b: i32, q: i32) -> i32 {
        ((a as i64 * b as i64) % q as i64) as i32
    }

    fn mod_inverse(&self, a: i32, q: i32) -> i32 {
        // Extended Euclidean algorithm
        let mut m = q;
        let mut x = 0;
        let mut y = 1;
        if m == 1 {
            return 0;
        }
        let mut a = a;
        while a > 1 {
            let q = a / m;
            let t = m;
            m = a % m;
            a = t;
            let t = x;
            x = y - q * x;
            y = t;
        }
        if y < 0 {
            y += q;
        }
        y
    }
}
