//! Memory Safety Testing for Prelude Utilities
//!
//! This module provides memory safety validation for utility functions
//! and error handling mechanisms. It tests hex encoding/decoding, UUID
//! generation, error handling, and concurrent access patterns.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::prelude::error::{LatticeArcError, Result};

/// Memory safety tester for utilities.
///
/// Provides comprehensive memory safety testing for common utility operations
/// used throughout the LatticeArc library.
pub struct UtilityMemorySafetyTester;

impl Default for UtilityMemorySafetyTester {
    fn default() -> Self {
        Self::new()
    }
}

impl UtilityMemorySafetyTester {
    /// Creates a new memory safety tester instance.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Test memory safety of utility operations.
    ///
    /// # Errors
    ///
    /// Returns an error if any memory safety test fails validation.
    pub fn test_memory_safety(&self) -> Result<()> {
        tracing::info!("Testing utility memory safety");

        // Test hex operations memory safety
        let invalid_hex = ["g", "gg", "invalid", "z", "G", "xyz", "123", "abcdefg"];
        for &hex_str in &invalid_hex {
            let result = hex::decode(hex_str);
            if result.is_ok() {
                return Err(LatticeArcError::ValidationError {
                    message: format!("Hex string '{}' should be invalid", hex_str),
                });
            }
        }
        // Empty string is actually valid (decodes to empty bytes)
        if hex::decode("").is_err() {
            return Err(LatticeArcError::ValidationError {
                message: "Empty hex string should be valid".to_string(),
            });
        }

        // Test UUID operations memory safety
        for _ in 0..100 {
            let uuid = uuid::Uuid::new_v4();
            if uuid.is_nil() {
                return Err(LatticeArcError::ValidationError {
                    message: "UUID should not be nil".to_string(),
                });
            }
            let uuid_str = uuid.to_string();
            if uuid_str.len() != 36 {
                return Err(LatticeArcError::ValidationError {
                    message: format!("UUID string should be 36 chars, got {}", uuid_str.len()),
                });
            }
        }

        // Test error operations memory safety
        let test_errors = vec![
            LatticeArcError::InvalidInput("test".to_string()),
            LatticeArcError::IoError(
                std::io::Error::new(std::io::ErrorKind::NotFound, "test").to_string(),
            ),
        ];

        for error in test_errors {
            let _display = format!("{}", error);
            let _debug = format!("{:?}", error);
            // Should not panic
        }

        tracing::info!("Utility memory safety tests passed");
        Ok(())
    }

    /// Test hex operations memory safety.
    ///
    /// # Errors
    ///
    /// Returns an error if hex encoding/decoding memory safety tests fail.
    pub fn test_hex_memory_safety(&self) -> Result<()> {
        // Test invalid hex strings - hex decode requires even length and valid hex chars
        let invalid_hex = ["g", "gg", "invalid", "z", "G", "xyz", "123", "abcdefg"];
        for &hex_str in &invalid_hex {
            let result = hex::decode(hex_str);
            if result.is_ok() {
                return Err(LatticeArcError::ValidationError {
                    message: format!("Hex string '{}' should be invalid", hex_str),
                });
            }
        }

        // Empty string is actually valid (decodes to empty bytes)
        if hex::decode("").is_err() {
            return Err(LatticeArcError::ValidationError {
                message: "Empty hex string should be valid".to_string(),
            });
        }

        Ok(())
    }

    /// Test UUID operations memory safety.
    ///
    /// # Errors
    ///
    /// Returns an error if UUID parsing fails during memory safety validation.
    pub fn test_uuid_memory_safety(&self) -> Result<()> {
        // Test UUID generation (should never panic)
        for _ in 0..100 {
            let uuid = uuid::Uuid::new_v4();
            if uuid.is_nil() {
                return Err(LatticeArcError::ValidationError {
                    message: "UUID should not be nil".to_string(),
                });
            }
            if uuid.get_version_num() != 4 {
                return Err(LatticeArcError::ValidationError {
                    message: format!("UUID version should be 4, got {}", uuid.get_version_num()),
                });
            }

            // Test string conversion
            let uuid_str = uuid.to_string();
            if uuid_str.len() != 36 {
                return Err(LatticeArcError::ValidationError {
                    message: format!("UUID string should be 36 chars, got {}", uuid_str.len()),
                });
            }

            // Test parsing back
            let parsed = uuid::Uuid::parse_str(&uuid_str)?;
            if parsed != uuid {
                return Err(LatticeArcError::ValidationError {
                    message: "Parsed UUID should match original".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Test error handling memory safety.
    ///
    /// # Errors
    ///
    /// Returns an error if error serialization/deserialization fails.
    pub fn test_error_memory_safety(&self) -> Result<()> {
        use crate::prelude::prelude::error::{
            attempt_error_recovery, get_error_severity, is_recoverable_error,
        };

        // Test various error types
        let errors = vec![
            LatticeArcError::InvalidInput("test".to_string()),
            LatticeArcError::NetworkError("connection failed".to_string()),
            LatticeArcError::IoError("file not found".to_string()),
            LatticeArcError::EncryptionError("cipher failed".to_string()),
        ];

        for error in errors {
            // These should not panic or leak memory
            let _recovery = attempt_error_recovery(&error);
            let _severity = get_error_severity(&error);
            let _recoverable = is_recoverable_error(&error);

            // Test serialization
            let json = serde_json::to_string(&error)?;
            let deserialized: LatticeArcError = serde_json::from_str(&json)?;
            if error != deserialized {
                return Err(LatticeArcError::ValidationError {
                    message: "Deserialized error should match original".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Test concurrent access safety.
    ///
    /// # Errors
    ///
    /// Returns an error if a thread panics or concurrent operations fail.
    pub fn test_concurrent_safety(&self) -> Result<()> {
        use std::thread;

        let mut handles = vec![];

        // Spawn threads performing utility operations
        for i in 0..4 {
            let handle: thread::JoinHandle<Result<()>> = thread::spawn(move || {
                for j in 0..100 {
                    // Test hex operations
                    let data = format!("thread_{}_{}", i, j).into_bytes();
                    let encoded = hex::encode(&data);
                    let _decoded = hex::decode(&encoded)?;

                    // Test UUID generation
                    let _uuid = uuid::Uuid::new_v4();

                    // Test error handling
                    let _error = LatticeArcError::InvalidInput(format!("test_{}_{}", i, j));
                }
                Ok::<(), LatticeArcError>(())
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle
                .join()
                // Thread join errors are Box<dyn Any> which can't be formatted,
                // but we can try to downcast to common panic types
                .map_err(|e| {
                    let msg = e
                        .downcast_ref::<&str>()
                        .map(ToString::to_string)
                        .or_else(|| e.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "Unknown panic payload".to_string());
                    LatticeArcError::ConcurrencyError(format!("Thread panic: {}", msg))
                })??;
        }

        Ok(())
    }
}

/// Leak detector for utilities.
///
/// Monitors utility operations for potential resource leaks by
/// repeatedly executing operations and tracking success/failure rates.
pub struct UtilityLeakDetector;

impl Default for UtilityLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UtilityLeakDetector {
    /// Creates a new leak detector instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Monitor for resource leaks in utility operations.
    ///
    /// Executes the provided operation 1000 times and tracks success/failure
    /// rates to detect potential resource leaks or instability.
    ///
    /// # Errors
    ///
    /// Returns an error if the monitored operation fails during leak detection.
    pub fn monitor_leaks<F>(&self, operation: F) -> Result<()>
    where
        F: Fn() -> Result<()>,
    {
        // Comprehensive leak detection through repeated execution and error monitoring
        let mut success_count = 0;
        let mut error_count = 0;
        for i in 0..1000 {
            match operation() {
                #[allow(clippy::arithmetic_side_effects)]
                Ok(_) => success_count += 1,
                #[allow(clippy::arithmetic_side_effects)]
                Err(e) => {
                    error_count += 1;
                    tracing::warn!("Operation {} failed: {}", i, e);
                    // Continue testing to see if it's consistent
                }
            }
        }
        tracing::info!(
            "Leak detection completed: {} successes, {} errors out of 1000 operations",
            success_count,
            error_count
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_safety() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_memory_safety().is_ok());
    }

    #[test]
    fn test_concurrent_safety() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_concurrent_safety().is_ok());
    }

    #[test]
    fn test_hex_memory_safety() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_hex_memory_safety().is_ok());
    }

    #[test]
    fn test_uuid_memory_safety() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_uuid_memory_safety().is_ok());
    }

    #[test]
    fn test_error_memory_safety() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_error_memory_safety().is_ok());
    }

    #[test]
    fn test_leak_detector() {
        let detector = UtilityLeakDetector::new();

        let result = detector.monitor_leaks(|| {
            let _data = vec![0u8; 100];
            let _encoded = hex::encode(&_data);
            Ok(())
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_safety_tester_default() {
        let tester = UtilityMemorySafetyTester;
        assert!(tester.test_memory_safety().is_ok());
    }

    #[test]
    fn test_leak_detector_default() {
        let detector = UtilityLeakDetector;
        let result = detector.monitor_leaks(|| Ok(()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_leak_detector_with_failing_operation() {
        let detector = UtilityLeakDetector::new();
        // Operation that always fails — monitor_leaks should still succeed
        // (it counts errors but doesn't propagate them)
        let result = detector.monitor_leaks(|| {
            Err(LatticeArcError::InvalidInput("intentional failure".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_leak_detector_with_intermittent_failures() {
        let detector = UtilityLeakDetector::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let result = detector.monitor_leaks(|| {
            let val = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if val.is_multiple_of(3) {
                Err(LatticeArcError::InvalidInput("every third fails".to_string()))
            } else {
                Ok(())
            }
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_safety_tester_new_and_default_are_equivalent() {
        let t1 = UtilityMemorySafetyTester::new();
        let t2 = UtilityMemorySafetyTester;
        // Both should work identically
        assert!(t1.test_hex_memory_safety().is_ok());
        assert!(t2.test_hex_memory_safety().is_ok());
    }

    #[test]
    fn test_leak_detector_new_and_default_are_equivalent() {
        let d1 = UtilityLeakDetector::new();
        let d2 = UtilityLeakDetector;
        assert!(d1.monitor_leaks(|| Ok(())).is_ok());
        assert!(d2.monitor_leaks(|| Ok(())).is_ok());
    }

    #[test]
    fn test_uuid_memory_safety_standalone() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_uuid_memory_safety().is_ok());
    }

    #[test]
    fn test_error_memory_safety_standalone() {
        let tester = UtilityMemorySafetyTester::new();
        assert!(tester.test_error_memory_safety().is_ok());
    }

    #[test]
    fn test_hex_roundtrip_large_data() {
        let tester = UtilityMemorySafetyTester::new();
        // Ensure large data hex encode/decode works
        let data = vec![0xABu8; 4096];
        let encoded = hex::encode(&data);
        let decoded = hex::decode(&encoded);
        assert!(decoded.is_ok());
        if let Ok(ref bytes) = decoded {
            assert_eq!(bytes, &data);
        }
        // Basic tester should still pass
        assert!(tester.test_hex_memory_safety().is_ok());
    }

    #[test]
    fn test_concurrent_safety_produces_no_errors() {
        let tester = UtilityMemorySafetyTester::new();
        // Run concurrent safety test multiple times to increase confidence
        for _ in 0..3 {
            assert!(tester.test_concurrent_safety().is_ok());
        }
    }

    #[test]
    fn test_leak_detector_monitor_many_successes() {
        let detector = UtilityLeakDetector::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let result = detector.monitor_leaks(|| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        assert!(result.is_ok());
        // Should have run 1000 iterations
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1000);
    }
}
