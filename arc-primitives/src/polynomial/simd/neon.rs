//! ARM NEON SIMD-accelerated polynomial operations
//!
//! Provides high-performance NEON implementations for NTT and polynomial
//! arithmetic on ARM64 platforms.

#![cfg(target_arch = "aarch64")]

use super::constants::{MLKEM_N, MLKEM_Q, MONT_SQ_INV, QINV, ZETAS};
use std::simd::num::SimdInt;
use std::simd::i32x4;

/// SIMD-accelerated Montgomery reduction for NEON
#[inline]
pub fn montgomery_reduce_simd_neon(a: i32x4) -> i32x4 {
    let qinv = i32x4::splat(QINV);
    let q = i32x4::splat(MLKEM_Q);

    // t = ((a as i32) * QINV) as i64
    let a_i64 = a.cast::<i64>();
    let qinv_i64 = qinv.cast::<i64>();
    let t = (a_i64 * qinv_i64) >> 16;

    // u = (a - t * MLKEM_Q) >> 16
    let q_i64 = q.cast::<i64>();
    let u = (a_i64 - t * q_i64) >> 16;

    u.cast::<i32>()
}

/// SIMD-accelerated Barrett reduction for NEON
#[inline]
pub fn barrett_reduce_simd_neon(a: i32x4) -> i32x4 {
    let v = i32x4::splat(((1i64 << 26) + (MLKEM_Q >> 1) as i64) as i32 / MLKEM_Q);
    let t = ((v.cast::<i64>() * a.cast::<i64>() + (1i64 << 25)) >> 26).cast::<i32>();
    a - t * i32x4::splat(MLKEM_Q)
}

/// SIMD-accelerated base multiplication for NEON
#[inline]
pub fn basemul_simd_neon(a: i32x4, b: i32x4, zeta: i32x4) -> i32x4 {
    // Extract individual coefficients for complex multiplication
    let a0 = i32x4::splat(a[0]);
    let a1 = i32x4::splat(a[1]);
    let b0 = i32x4::splat(b[0]);
    let b1 = i32x4::splat(b[1]);

    // Compute zeta * a1 * b1
    let zeta_a1_b1 = montgomery_reduce_simd_neon(montgomery_reduce_simd_neon(a1 * b1) * zeta);

    // Compute final results
    let r0 = montgomery_reduce_simd_neon(a0 * b0) + zeta_a1_b1;
    let r1 = montgomery_reduce_simd_neon(a0 * b1) + montgomery_reduce_simd_neon(a1 * b0);

    // Interleave results for output
    let mut result = i32x4::splat(0);
    for i in 0..2 {
        result[2*i] = r0[i];
        result[2*i + 1] = r1[i];
    }
    result
}

/// NEON-accelerated NTT implementation
pub fn ntt_neon(r: &mut [i32; MLKEM_N]) {
    let mut len = 128;
    let mut k = 1;

    while len >= 4 {  // Process 4 elements at a time with NEON
        let mut start = 0;
        while start < MLKEM_N {
            let zeta = ZETAS[k - 1];
            k += 1;

            let mut j = start;
            while j < start + len {
                // Load 4 elements at once
                let r_chunk = i32x4::from_slice(&r[j..j + 4]);
                let r_len_chunk = i32x4::from_slice(&r[j + len..j + len + 4]);

                // Compute t = montgomery_reduce(zeta * r[j + len])
                let zeta_vec = i32x4::splat(zeta);
                let t = montgomery_reduce_simd_neon(zeta_vec * r_len_chunk.cast::<i64>()).cast::<i32>();

                // Butterfly operations: r[j + len] = r[j] - t, r[j] = r[j] + t
                let new_r_len = r_chunk - t;
                let new_r = r_chunk + t;

                // Store results back
                r[j..j + 4].copy_from_slice(new_r.as_array());
                r[j + len..j + len + 4].copy_from_slice(new_r_len.as_array());

                j += 4;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// NEON-accelerated inverse NTT implementation
pub fn invntt_neon(r: &mut [i32; MLKEM_N]) {
    let mut len = 2;
    let mut k = 127;

    while len <= 64 {  // Process up to 4 elements at a time
        let mut start = 0;
        while start < MLKEM_N {
            let zeta = ZETAS[k];
            k -= 1;

            let mut j = start;
            while j < start + len {
                // Load 4 elements at once
                let r_chunk = i32x4::from_slice(&r[j..j + 4]);
                let r_len_chunk = i32x4::from_slice(&r[j + len..j + len + 4]);

                // Butterfly operations for inverse NTT
                let t = r_chunk;
                let new_r = barrett_reduce_simd_neon((t + r_len_chunk).cast::<i32>());
                let mut new_r_len = t - r_len_chunk;
                new_r_len = montgomery_reduce_simd_neon((zeta as i64 * new_r_len.cast::<i64>()).cast::<i32>());

                // Store results back
                r[j..j + 4].copy_from_slice(new_r.as_array());
                r[j + len..j + len + 4].copy_from_slice(new_r_len.as_array());

                j += 4;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Final scaling by 1/128 using SIMD
    let scale_factor = i32x4::splat(MONT_SQ_INV);
    for i in (0..MLKEM_N).step_by(4) {
        let chunk = i32x4::from_slice(&r[i..i + 4]);
        let scaled = montgomery_reduce_simd_neon(chunk.cast::<i64>() * scale_factor.cast::<i64>()).cast::<i32>();
        r[i..i + 4].copy_from_slice(scaled.as_array());
    }
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
    fn test_neon_ntt_constant_time() {
        let test_polynomials = [
            [0i32; MLKEM_N],
            core::array::from_fn(|i| (i % 4) as i32),
            core::array::from_fn(|i| ((i * 13) % 3329) as i32),
        ];

        for (i, poly) in test_polynomials.iter().enumerate() {
            let variance = measure_timing_variance(
                || {
                    let mut poly_copy = *poly;
                    ntt_neon(&mut poly_copy);
                },
                150
            );

            assert!(
                variance < 10.0,
                "NEON NTT shows high timing variance ({:.2}%) for polynomial {}",
                variance, i
            );
        }
    }

    #[test]
    fn test_montgomery_reduce_neon_constant_time() {
        let test_inputs = [
            i32x4::from_array([0, 1, 42, 1000]),
            i32x4::from_array([-1, -42, -1000, -3328]),
            i32x4::from_array([100, 200, 300, 400]),
        ];

        for (i, &input) in test_inputs.iter().enumerate() {
            let variance = measure_timing_variance(
                || {
                    let _result = montgomery_reduce_simd_neon(input);
                },
                1000
            );

            assert!(
                variance < 10.0,
                "NEON Montgomery reduction shows high timing variance ({:.2}%) for input {}",
                variance, i
            );
        }
    }
}
