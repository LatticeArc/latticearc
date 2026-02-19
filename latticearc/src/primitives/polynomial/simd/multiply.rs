//! High-level polynomial multiplication with runtime dispatch
//!
//! Provides unified API for polynomial multiplication that automatically
//! selects the best available implementation based on platform capabilities.

use super::constants::{MLKEM_N, ZETAS};
use super::ntt::{basemul, invntt, ntt};

#[cfg(target_feature = "avx2")]
use super::avx2::{basemul_simd, invntt_avx2, ntt_avx2};

#[cfg(target_arch = "aarch64")]
use super::neon::{basemul_simd_neon, invntt_neon, ntt_neon};

/// Full polynomial multiplication using NTT (scalar implementation)
/// Multiplies two polynomials in R_q using NTT for efficiency
pub fn polynomial_multiply_ntt(a: &[i32; MLKEM_N], b: &[i32; MLKEM_N]) -> [i32; MLKEM_N] {
    let mut a_ntt = *a;
    let mut b_ntt = *b;
    let mut result = [0i32; MLKEM_N];

    // Convert to NTT domain
    ntt(&mut a_ntt);
    ntt(&mut b_ntt);

    // Pointwise multiplication in NTT domain
    for i in (0..MLKEM_N).step_by(2) {
        // Bounds are guaranteed by array sizes and step_by(2)
        let a_slice = &a_ntt[i..i+2];
        let b_slice = &b_ntt[i..i+2];
        let a_arr: &[i32; 2] = match a_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => continue,
        };
        let b_arr: &[i32; 2] = match b_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => continue,
        };
        if let Some(r_slice) = result.get_mut(i..i+2) {
            if let Ok(r_arr) = <&mut [i32] as TryInto<&mut [i32; 2]>>::try_into(r_slice) {
                basemul(r_arr, a_arr, b_arr, ZETAS[i/2]);
            }
        }
    }

    // Convert back to coefficient domain
    invntt(&mut result);

    result
}

/// AVX2-accelerated NTT polynomial multiplication
#[cfg(target_feature = "avx2")]
pub fn polynomial_multiply_avx2(a: &[i32; MLKEM_N], b: &[i32; MLKEM_N]) -> [i32; MLKEM_N] {
    use std::simd::i32x8;

    let mut a_ntt = *a;
    let mut b_ntt = *b;
    let mut result = [0i32; MLKEM_N];

    // Forward NTT with AVX2 acceleration
    ntt_avx2(&mut a_ntt);
    ntt_avx2(&mut b_ntt);

    // Pointwise multiplication in NTT domain with SIMD
    for i in (0..MLKEM_N).step_by(8) {
        let a_chunk = i32x8::from_slice(&a_ntt[i..i + 8]);
        let b_chunk = i32x8::from_slice(&b_ntt[i..i + 8]);
        let zeta_chunk = i32x8::from_slice(&ZETAS[i/8..i/8 + 8]);
        let mul_result = basemul_simd(a_chunk, b_chunk, zeta_chunk);
        result[i..i + 8].copy_from_slice(mul_result.as_array());
    }

    // Inverse NTT with AVX2 acceleration
    invntt_avx2(&mut result);

    result
}

/// ARM NEON-accelerated NTT polynomial multiplication
#[cfg(target_arch = "aarch64")]
pub fn polynomial_multiply_neon(a: &[i32; MLKEM_N], b: &[i32; MLKEM_N]) -> [i32; MLKEM_N] {
    use std::simd::i32x4;

    let mut a_ntt = *a;
    let mut b_ntt = *b;
    let mut result = [0i32; MLKEM_N];

    // Forward NTT with NEON acceleration
    ntt_neon(&mut a_ntt);
    ntt_neon(&mut b_ntt);

    // Pointwise multiplication in NTT domain with SIMD
    for i in (0..MLKEM_N).step_by(4) {
        let a_chunk = i32x4::from_slice(&a_ntt[i..i + 4]);
        let b_chunk = i32x4::from_slice(&b_ntt[i..i + 4]);
        let zeta_chunk = i32x4::from_slice(&ZETAS[i/4..i/4 + 4]);
        let mul_result = basemul_simd_neon(a_chunk, b_chunk, zeta_chunk);
        result[i..i + 4].copy_from_slice(mul_result.as_array());
    }

    // Inverse NTT with NEON acceleration
    invntt_neon(&mut result);

    result
}

/// Fallback NTT implementation for systems without SIMD support
#[cfg(not(any(target_feature = "avx2", target_arch = "aarch64")))]
pub fn polynomial_multiply_simd(a: &[i32; MLKEM_N], b: &[i32; MLKEM_N]) -> [i32; MLKEM_N] {
    polynomial_multiply_ntt(a, b)
}

/// Runtime dispatch for polynomial multiplication
/// Automatically selects the best available implementation
pub fn polynomial_multiply(a: &[i32; MLKEM_N], b: &[i32; MLKEM_N]) -> [i32; MLKEM_N] {
    #[cfg(target_feature = "avx2")]
    {
        polynomial_multiply_avx2(a, b)
    }

    #[cfg(all(target_arch = "aarch64", not(target_feature = "avx2")))]
    {
        polynomial_multiply_neon(a, b)
    }

    #[cfg(not(any(target_feature = "avx2", target_arch = "aarch64")))]
    {
        polynomial_multiply_ntt(a, b)
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
    fn test_polynomial_multiply_constant_time() {
        let test_pairs = [
            ([0i32; MLKEM_N], [0i32; MLKEM_N]),
            (
                core::array::from_fn(|i| (i % 10) as i32),
                core::array::from_fn(|i| ((i + 1) % 10) as i32),
            ),
            (
                core::array::from_fn(|i| (i * i % 3329) as i32),
                core::array::from_fn(|i| ((i * i * i) % 3329) as i32),
            ),
        ];

        for (a, b) in &test_pairs {
            let variance = measure_timing_variance(
                || {
                    let _result = polynomial_multiply(a, b);
                },
                200
            );

            assert!(
                variance < 10.0,
                "Polynomial multiplication shows high timing variance ({:.2}%)",
                variance
            );
        }
    }

    #[test]
    fn test_simd_scalar_consistency() {
        let test_a: [i32; MLKEM_N] = core::array::from_fn(|i| (i % 100) as i32);
        let test_b: [i32; MLKEM_N] = core::array::from_fn(|i| ((i + 50) % 100) as i32);

        let result_scalar = polynomial_multiply_ntt(&test_a, &test_b);
        let result_dispatch = polynomial_multiply(&test_a, &test_b);

        assert_eq!(result_scalar, result_dispatch,
            "SIMD and scalar implementations produce different results");
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_avx2_implementation() {
        let a: [i32; MLKEM_N] = core::array::from_fn(|i| (i % 10) as i32);
        let b: [i32; MLKEM_N] = core::array::from_fn(|i| ((i + 1) % 10) as i32);
        let result = polynomial_multiply_avx2(&a, &b);

        let expected = polynomial_multiply_ntt(&a, &b);
        assert_eq!(result, expected);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_neon_implementation() {
        let a: [i32; MLKEM_N] = core::array::from_fn(|i| (i % 10) as i32);
        let b: [i32; MLKEM_N] = core::array::from_fn(|i| ((i + 1) % 10) as i32);
        let result = polynomial_multiply_neon(&a, &b);

        let expected = polynomial_multiply_ntt(&a, &b);
        assert_eq!(result, expected);
    }
}
