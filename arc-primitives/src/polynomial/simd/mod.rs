#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SIMD-accelerated polynomial operations for lattice-based cryptography
//!
//! This module provides high-performance SIMD implementations for polynomial
//! arithmetic used in post-quantum cryptographic schemes like ML-KEM and ML-DSA.
//!
//! Implements Number Theoretic Transform (NTT) for efficient polynomial multiplication
//! in the ring R_q = Z_q[X]/(X^256 + 1) with q = 3329.
//!
//! ## Module Organization
//!
//! - [`constants`] - ML-KEM parameters and NTT twiddle factors
//! - [`reduction`] - Montgomery and Barrett modular reduction
//! - [`ntt`] - Scalar NTT/INTT and base multiplication
//! - [`avx2`] - AVX2 SIMD implementations (x86_64)
//! - [`neon`] - NEON SIMD implementations (ARM64)
//! - [`multiply`] - High-level polynomial multiplication with runtime dispatch
//!
//! ## Platform Support
//!
//! The module automatically selects the best available implementation:
//! - **AVX2**: Used on x86_64 with AVX2 support
//! - **NEON**: Used on ARM64 platforms
//! - **Scalar**: Fallback for other platforms
//!
//! ## Usage
//!
//! ```rust,ignore
//! use arc_primitives::polynomial::simd::{polynomial_multiply, MLKEM_N};
//!
//! let a: [i32; MLKEM_N] = [1, 2, 3, /* ... */];
//! let b: [i32; MLKEM_N] = [4, 5, 6, /* ... */];
//! let result = polynomial_multiply(&a, &b);
//! ```

pub mod constants;
pub mod reduction;
pub mod ntt;
pub mod multiply;

#[cfg(target_feature = "avx2")]
pub mod avx2;

#[cfg(target_arch = "aarch64")]
pub mod neon;

// Re-export commonly used items
pub use constants::{MLKEM_N, MLKEM_Q, ZETAS};
pub use reduction::{barrett_reduce, montgomery_reduce};
pub use ntt::{basemul, invntt, ntt};
pub use multiply::{polynomial_multiply, polynomial_multiply_ntt};

#[cfg(target_feature = "avx2")]
pub use avx2::{barrett_reduce_simd, basemul_simd, invntt_avx2, montgomery_reduce_simd, ntt_avx2};
#[cfg(target_feature = "avx2")]
pub use multiply::polynomial_multiply_avx2;

#[cfg(target_arch = "aarch64")]
pub use neon::{barrett_reduce_simd_neon, basemul_simd_neon, invntt_neon, montgomery_reduce_simd_neon, ntt_neon};
#[cfg(target_arch = "aarch64")]
pub use multiply::polynomial_multiply_neon;

#[cfg(not(any(target_feature = "avx2", target_arch = "aarch64")))]
pub use multiply::polynomial_multiply_simd;
