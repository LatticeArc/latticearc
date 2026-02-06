//! Concurrency Tests
//!
//! Verifies thread-safe operation of LatticeArc cryptographic primitives.
//!
//! ## Test Categories
//!
//! - **Parallel Key Generation**: No race conditions in keygen
//! - **Concurrent Operations**: Safe encrypt/decrypt from multiple threads
//! - **RNG Safety**: Thread-local RNG isolation
//!
//! Note: Additional concurrency tests are in `arc-primitives/tests/concurrency_tests.rs`

pub mod parallel_keygen;
pub mod thread_safety;

#[cfg(test)]
mod tests {
    #[test]
    fn concurrency_modules_load() {
        // Ensures all concurrency test modules compile correctly
    }
}
