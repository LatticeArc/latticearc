//! Number Theoretic Transform (NTT) operations
//!
//! Implements forward and inverse NTT for efficient polynomial multiplication
//! in the ring R_q = Z_q[X]/(X^256 + 1).

use super::constants::{MLKEM_N, MONT_SQ_INV, ZETAS};
use super::reduction::{barrett_reduce, montgomery_reduce};

/// Forward Number Theoretic Transform (NTT)
/// Transforms polynomial from coefficient domain to NTT domain
pub fn ntt(r: &mut [i32; MLKEM_N]) {
    let mut len = 128;
    let mut k = 1;

    while len >= 2 {
        let mut start = 0;
        while start < MLKEM_N {
            let zeta = ZETAS[k - 1];
            k += 1;

            let mut j = start;
            while j < start + len {
                if let (Some(&r_j), Some(r_j_len)) = (r.get(j), r.get(j + len)) {
                    let t = montgomery_reduce(zeta as i64 * (*r_j_len) as i64);
                    if let Some(r_len_pos) = r.get_mut(j + len) {
                        *r_len_pos = *r_j - t;
                    }
                    if let Some(r_pos) = r.get_mut(j) {
                        *r_pos += t;
                    }
                }
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse Number Theoretic Transform (INTT)
/// Transforms polynomial from NTT domain back to coefficient domain
pub fn invntt(r: &mut [i32; MLKEM_N]) {
    let mut len = 2;
    let mut k = 127;

    while len <= 128 {
        let mut start = 0;
        while start < MLKEM_N {
            let zeta = ZETAS[k];
            k -= 1;

            let mut j = start;
            while j < start + len {
                if let (Some(&r_j), Some(&r_j_len)) = (r.get(j), r.get(j + len)) {
                    // Compute new values before mutating to avoid borrow conflicts
                    let new_r_j = barrett_reduce(r_j + r_j_len);
                    let diff = r_j_len - r_j;
                    let new_r_j_len = montgomery_reduce(zeta as i64 * diff as i64);

                    if let Some(r_pos) = r.get_mut(j) {
                        *r_pos = new_r_j;
                    }
                    if let Some(r_len_pos) = r.get_mut(j + len) {
                        *r_len_pos = new_r_j_len;
                    }
                }
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Final scaling by 1/128
    for i in 0..MLKEM_N {
        if let Some(&r_val) = r.get(i) {
            if let Some(r_pos) = r.get_mut(i) {
                *r_pos = montgomery_reduce(r_val as i64 * MONT_SQ_INV as i64);
            }
        }
    }
}

/// Base multiplication in NTT domain
/// Multiplies two polynomials modulo X^2 - zeta
pub fn basemul(r: &mut [i32; 2], a: &[i32; 2], b: &[i32; 2], zeta: i32) {
    let zeta_a1_b1 = montgomery_reduce(montgomery_reduce(a[1] as i64 * b[1] as i64) as i64 * zeta as i64);
    r[0] = montgomery_reduce(a[0] as i64 * b[0] as i64) + zeta_a1_b1;
    r[1] = montgomery_reduce(a[0] as i64 * b[1] as i64) + montgomery_reduce(a[1] as i64 * b[0] as i64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn measure_timing_variance<F>(operation: F, iterations: usize) -> f64
    where
        F: Fn() -> (),
    {
        let mut times = Vec::with_capacity(iterations);

        for _ in 0..10 {
            operation();
        }

        for _ in 0..iterations {
            let start = Instant::now();
            operation();
            let elapsed = start.elapsed();
            times.push(elapsed.as_nanos() as f64);
        }

        let mean: f64 = times.iter().sum::<f64>() / iterations as f64;
        let variance = times.iter()
            .map(|&t| {
                let diff = t - mean;
                diff * diff
            })
            .sum::<f64>() / iterations as f64;

        variance.sqrt() / mean * 100.0
    }

    #[test]
    fn test_basemul_constant_time() {
        let test_pairs = [
            ([0, 0], [0, 0]),
            ([1, 1], [1, 1]),
            ([42, 100], [200, 300]),
            ([1000, 2000], [3000, 4000]),
            ([3328, 3328], [3328, 3328]),
            ([-1, -1], [-1, -1]),
        ];

        let zeta_values = [1, -1, 100, -100, 1044, -1044];

        for (a, b) in &test_pairs {
            for &zeta in &zeta_values {
                let variance = measure_timing_variance(
                    || {
                        let mut result = [0i32; 2];
                        basemul(&mut result, a, b, zeta);
                    },
                    1000
                );

                assert!(
                    variance < 10.0,
                    "Base multiplication shows high timing variance ({:.2}%)",
                    variance
                );
            }
        }
    }

    #[test]
    fn test_ntt_constant_time() {
        let test_polynomials = [
            [0i32; MLKEM_N],
            core::array::from_fn(|i| (i % 10) as i32),
            core::array::from_fn(|i| (i * i % 3329) as i32),
        ];

        for poly in &test_polynomials {
            let variance = measure_timing_variance(
                || {
                    let mut poly_copy = *poly;
                    ntt(&mut poly_copy);
                },
                500
            );

            assert!(
                variance < 10.0,
                "NTT shows high timing variance ({:.2}%)",
                variance
            );
        }
    }

    #[test]
    fn test_invntt_constant_time() {
        let test_polynomials = [
            [0i32; MLKEM_N],
            core::array::from_fn(|i| (i % 10) as i32),
            core::array::from_fn(|i| (i * i % 3329) as i32),
        ];

        for poly in &test_polynomials {
            let variance = measure_timing_variance(
                || {
                    let mut poly_copy = *poly;
                    invntt(&mut poly_copy);
                },
                500
            );

            assert!(
                variance < 10.0,
                "Inverse NTT shows high timing variance ({:.2}%)",
                variance
            );
        }
    }

    #[test]
    fn test_basemul_deterministic() {
        let test_vectors = [
            ([0, 0], [0, 0]),
            ([1, 1], [1, 1]),
            ([42, 100], [200, 300]),
        ];

        for (a, b) in &test_vectors {
            for &zeta in &[1, -1, 100, -100] {
                let mut result1 = [0i32; 2];
                let mut result2 = [0i32; 2];

                basemul(&mut result1, a, b, zeta);
                basemul(&mut result2, a, b, zeta);

                assert_eq!(result1, result2,
                    "Base multiplication produces non-deterministic results");
            }
        }
    }
}
