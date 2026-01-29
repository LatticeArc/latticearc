#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: FIPS global state management for validation.
// - Initialization and state tracking for FIPS mode
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

//! Global FIPS state management and initialization functions

use arc_prelude::error::LatticeArcError;
use rand::RngCore;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::ValidationScope;
use super::types::ValidationResult;
use super::validator::FIPSValidator;

pub(crate) static FIPS_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static FIPS_VALIDATION_RESULT: Mutex<Option<ValidationResult>> = Mutex::new(None);

/// Initialize FIPS mode with power-on self-tests.
///
/// # Errors
/// Returns an error if the module validation fails or the validation result lock cannot be acquired.
pub fn init() -> Result<(), LatticeArcError> {
    if FIPS_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    tracing::info!("Starting FIPS power-on self-tests");

    let validator = FIPSValidator::new(ValidationScope::FullModule);
    let result = validator.validate_module()?;

    if !result.is_valid {
        tracing::error!("FIPS power-on self-tests failed - aborting library initialization");
        std::process::abort();
    }

    if let Some(level) = result.level {
        tracing::info!("FIPS power-on self-tests passed - Level {:?}", level);
    } else {
        tracing::error!(
            "FIPS power-on self-tests passed but no security level achieved - aborting"
        );
        std::process::abort();
    }

    FIPS_VALIDATION_RESULT
        .lock()
        .map_err(|e| LatticeArcError::ValidationError {
            message: format!("Failed to acquire FIPS validation result lock: {}", e),
        })?
        .replace(result);

    FIPS_INITIALIZED.store(true, Ordering::Release);
    tracing::info!("FIPS validation completed successfully");

    Ok(())
}

/// Run conditional self-test for a specific algorithm.
///
/// # Errors
/// Returns an error if initialization fails or the specified algorithm test fails.
pub fn run_conditional_self_test(algorithm: &str) -> Result<(), LatticeArcError> {
    if !FIPS_INITIALIZED.load(Ordering::Acquire) {
        init()?;
    }

    let validator = FIPSValidator::new(ValidationScope::AlgorithmsOnly);

    match algorithm {
        "aes" | "AES" => {
            let result = validator.test_aes_algorithm()?;
            if !result.passed {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "AES conditional self-test failed: {}",
                        result.error_message.unwrap_or_default()
                    ),
                });
            }
        }
        "sha3" | "SHA3" => {
            let result = validator.test_sha3_algorithm()?;
            if !result.passed {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "SHA-3 conditional self-test failed: {}",
                        result.error_message.unwrap_or_default()
                    ),
                });
            }
        }
        "mlkem" | "MLKEM" => {
            let result = validator.test_mlkem_algorithm()?;
            if !result.passed {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "ML-KEM conditional self-test failed: {}",
                        result.error_message.unwrap_or_default()
                    ),
                });
            }
        }
        _ => {
            let result = validator.test_self_tests()?;
            if !result.passed {
                return Err(LatticeArcError::ValidationError {
                    message: format!(
                        "Self-test conditional check failed: {}",
                        result.error_message.unwrap_or_default()
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Perform continuous RNG health test per FIPS 140-3
///
/// # Errors
/// Returns an error if initialization fails or if the RNG produces identical consecutive samples.
pub fn continuous_rng_test() -> Result<(), LatticeArcError> {
    if !FIPS_INITIALIZED.load(Ordering::Acquire) {
        init()?;
    }

    let mut sample1 = [0u8; 32];
    let mut sample2 = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut sample1);
    rand::thread_rng().fill_bytes(&mut sample2);

    if sample1 == sample2 {
        return Err(LatticeArcError::ValidationError {
            message: "RNG continuous test failed: identical samples".to_string(),
        });
    }

    let mut bits_set = 0;
    for byte in sample1.iter().chain(sample2.iter()) {
        bits_set += byte.count_ones();
    }

    let total_bits = 64 * 8;
    let ones_ratio = f64::from(bits_set) / f64::from(total_bits);

    if !(0.4..=0.6).contains(&ones_ratio) {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "RNG continuous test failed: bit distribution out of range: {:.3}",
                ones_ratio
            ),
        });
    }

    Ok(())
}

/// Check if FIPS mode is initialized
pub fn is_fips_initialized() -> bool {
    FIPS_INITIALIZED.load(Ordering::Acquire)
}

/// Get the FIPS validation result if available
pub fn get_fips_validation_result() -> Option<ValidationResult> {
    FIPS_VALIDATION_RESULT.lock().ok().and_then(|result| result.clone())
}

/// Auto-initialize FIPS on library load
/// Can be disabled by setting FIPS_SKIP_AUTO_INIT=1 environment variable
///
/// # Note
/// Auto-init is DISABLED by default in library builds to avoid interfering with
/// test harnesses and applications that need control over initialization timing.
/// Applications should call `init()` explicitly when FIPS mode is required.
#[ctor::ctor]
fn fips_auto_init() {
    // Skip auto-init when explicitly disabled (default behavior)
    // To enable auto-init, set FIPS_ENABLE_AUTO_INIT=1
    if std::env::var("FIPS_ENABLE_AUTO_INIT").is_err() {
        return;
    }

    // Allow explicit skip as well
    if std::env::var("FIPS_SKIP_AUTO_INIT").is_ok() {
        return;
    }

    if let Err(e) = init() {
        // Use tracing instead of eprintln! for library code
        tracing::error!("FIPS initialization failed: {}", e);
        std::process::abort();
    }
}
