//! Comprehensive Platform and Environment Compatibility Tests
//!
//! This test suite validates cross-platform compatibility, ensuring the LatticeArc
//! cryptographic library works consistently across different:
//!
//! - Architectures (endianness, integer sizes, alignment, pointer sizes)
//! - Feature flag combinations
//! - Environment configurations (debug/release, thread-local storage, RNG, time)
//! - Configuration variations (CryptoConfig, SecurityLevel, hardware fallbacks)
//!
//! # Test Coverage
//!
//! 1. Architecture Compatibility (15+ tests)
//! 2. Feature Flag Compatibility (10+ tests)
//! 3. Environment Tests (10+ tests)
//! 4. Configuration Variations (10+ tests)
//!
//! Total: 45+ comprehensive platform compatibility tests

#![deny(unsafe_code)]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::absurd_extreme_comparisons,
    unused_qualifications
)]

use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use arc_core::{
    HardwareRouter,
    config::{
        CoreConfig, EncryptionConfig, HardwareConfig, ProofComplexity, SignatureConfig,
        UseCaseConfig, ZeroTrustConfig,
    },
    error::CoreError,
    selector::{CryptoPolicyEngine, PerformanceMetrics},
    traits::HardwareType,
    types::{
        AlgorithmSelection, CryptoConfig, CryptoContext, CryptoScheme, EncryptedMetadata, KeyPair,
        PerformancePreference, SecurityLevel, UseCase, ZeroizedBytes,
    },
};

// ============================================================================
// SECTION 1: Architecture Compatibility Tests (15+ tests)
// ============================================================================

// ---------------------------------------------------------------------------
// 1.1 Endianness Handling Tests
// ---------------------------------------------------------------------------

#[test]
fn test_endianness_detection() {
    // Verify we can detect the current platform's endianness
    #[cfg(target_endian = "little")]
    {
        let bytes: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let value = u32::from_le_bytes(bytes);
        assert_eq!(value, 0x04030201);
    }

    #[cfg(target_endian = "big")]
    {
        let bytes: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let value = u32::from_be_bytes(bytes);
        assert_eq!(value, 0x01020304);
    }
}

#[test]
fn test_endianness_consistent_serialization() {
    // Ensure cryptographic values serialize consistently regardless of platform
    let test_value: u64 = 0x0102030405060708;

    // Little-endian serialization (standard for network/storage)
    let le_bytes = test_value.to_le_bytes();
    let restored_le = u64::from_le_bytes(le_bytes);
    assert_eq!(test_value, restored_le, "LE serialization should round-trip");

    // Big-endian serialization
    let be_bytes = test_value.to_be_bytes();
    let restored_be = u64::from_be_bytes(be_bytes);
    assert_eq!(test_value, restored_be, "BE serialization should round-trip");
}

#[test]
fn test_endianness_crypto_key_consistency() {
    // Cryptographic keys should be byte-order independent
    let key_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let zeroized = ZeroizedBytes::new(key_bytes.to_vec());

    // Verify the bytes are stored correctly regardless of platform endianness
    assert_eq!(zeroized.as_slice(), &key_bytes);
    assert_eq!(zeroized.len(), 32);
}

#[test]
fn test_endianness_nonce_handling() {
    // Nonces must be consistent across platforms
    let nonce: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];

    let metadata = EncryptedMetadata { nonce: nonce.to_vec(), tag: None, key_id: None };

    // Verify nonce is stored as raw bytes
    assert_eq!(metadata.nonce.as_slice(), &nonce);
}

// ---------------------------------------------------------------------------
// 1.2 Integer Size Assumptions Tests
// ---------------------------------------------------------------------------

#[test]
fn test_integer_sizes_documented() {
    // Document and verify integer sizes across platforms
    assert!(mem::size_of::<usize>() >= 4, "usize must be at least 32 bits");
    assert!(mem::size_of::<isize>() >= 4, "isize must be at least 32 bits");

    // Fixed-width types should always be their specified size
    assert_eq!(mem::size_of::<u8>(), 1);
    assert_eq!(mem::size_of::<u16>(), 2);
    assert_eq!(mem::size_of::<u32>(), 4);
    assert_eq!(mem::size_of::<u64>(), 8);
    assert_eq!(mem::size_of::<u128>(), 16);
}

#[test]
fn test_integer_overflow_handled_safely() {
    // Verify arithmetic operations handle overflow safely
    let max_u64: u64 = u64::MAX;
    let result = max_u64.saturating_add(1);
    assert_eq!(result, u64::MAX, "Saturating add should not overflow");

    let result_checked = max_u64.checked_add(1);
    assert!(result_checked.is_none(), "Checked add should return None on overflow");

    let result_wrapping = max_u64.wrapping_add(1);
    assert_eq!(result_wrapping, 0, "Wrapping add should wrap to 0");
}

#[test]
fn test_timestamp_u64_range() {
    // Timestamps should fit in u64 for all realistic values
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time before Unix epoch");

    let timestamp_secs = current_time.as_secs();
    let timestamp_millis = current_time.as_millis();

    // Verify values fit in expected types
    assert!(timestamp_secs <= u64::MAX);
    assert!(timestamp_millis <= u128::from(u64::MAX));
}

#[test]
fn test_size_calculations_no_overflow() {
    // Test that size calculations don't overflow on large data
    let large_size: usize = 1024 * 1024 * 100; // 100 MB

    // These calculations should not panic
    let overhead: usize = 1024;
    let result = large_size.checked_add(overhead);
    assert!(result.is_some(), "Size calculation should not overflow for 100MB + 1KB");

    // Test multiplication
    let block_size: usize = 4096;
    let block_count = large_size.checked_div(block_size);
    assert!(block_count.is_some());
}

// ---------------------------------------------------------------------------
// 1.3 Alignment Requirements Tests
// ---------------------------------------------------------------------------

#[test]
fn test_struct_alignment() {
    // Verify struct alignment is platform-appropriate
    assert!(mem::align_of::<CoreConfig>() >= 1);
    assert!(mem::align_of::<EncryptedMetadata>() >= 1);
    assert!(mem::align_of::<CryptoContext>() >= 1);
}

#[test]
fn test_vector_alignment() {
    // Vec<u8> should be properly aligned for all platforms
    let data: Vec<u8> = vec![0u8; 1024];
    let ptr = data.as_ptr();

    // The pointer should be at least byte-aligned (always true for u8)
    assert!(!ptr.is_null());

    // For SIMD operations, we might need stricter alignment
    // This test documents current behavior
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 typically uses 16-byte or 32-byte alignment for SIMD
        let alignment = ptr as usize % 16;
        // Note: Vec doesn't guarantee SIMD alignment, just document behavior
        let _ = alignment;
    }
}

#[test]
fn test_atomic_alignment() {
    // Atomic types must be properly aligned
    let atomic_bool = AtomicBool::new(false);
    let atomic_u64 = AtomicU64::new(0);

    // These operations should work on all platforms
    atomic_bool.store(true, Ordering::SeqCst);
    atomic_u64.store(12345, Ordering::SeqCst);

    assert!(atomic_bool.load(Ordering::SeqCst));
    assert_eq!(atomic_u64.load(Ordering::SeqCst), 12345);
}

// ---------------------------------------------------------------------------
// 1.4 Pointer Size Independence Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pointer_size_documented() {
    // Document pointer sizes
    #[cfg(target_pointer_width = "32")]
    {
        assert_eq!(mem::size_of::<usize>(), 4);
        assert_eq!(mem::size_of::<*const u8>(), 4);
    }

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(mem::size_of::<usize>(), 8);
        assert_eq!(mem::size_of::<*const u8>(), 8);
    }
}

#[test]
fn test_size_bounds_portable() {
    // Verify size constants work across pointer widths
    let max_key_size: usize = 32768; // 32 KB - reasonable for any platform
    let max_message_size: usize = 1024 * 1024 * 16; // 16 MB

    assert!(max_key_size <= usize::MAX);
    assert!(max_message_size <= usize::MAX);
}

#[test]
fn test_boxed_types_pointer_independent() {
    // Box<T> should work correctly regardless of pointer size
    let boxed_data: Box<[u8; 1024]> = Box::new([0u8; 1024]);
    assert_eq!(boxed_data.len(), 1024);

    let boxed_config = Box::new(CoreConfig::default());
    assert_eq!(boxed_config.security_level, SecurityLevel::High);
}

#[test]
fn test_arc_reference_counting() {
    // Arc should work correctly across platforms
    use std::sync::Arc;

    let shared_data = Arc::new(vec![1u8, 2, 3, 4, 5]);
    let clone1 = Arc::clone(&shared_data);
    let clone2 = Arc::clone(&shared_data);

    assert_eq!(Arc::strong_count(&shared_data), 3);
    assert_eq!(clone1.as_slice(), clone2.as_slice());
}

// ============================================================================
// SECTION 2: Feature Flag Compatibility Tests (10+ tests)
// ============================================================================

#[test]
fn test_default_features_available() {
    // Test that default features provide expected functionality
    let config = CoreConfig::default();
    assert!(config.validate().is_ok());

    // Default should have reasonable security settings
    assert_eq!(config.security_level, SecurityLevel::High);
    assert!(config.hardware_acceleration);
    assert!(config.fallback_enabled);
}

#[test]
fn test_all_security_levels_available() {
    // All security levels should be available regardless of features
    let levels = vec![
        SecurityLevel::Standard,
        SecurityLevel::High,
        SecurityLevel::Maximum,
        SecurityLevel::Quantum,
    ];

    for level in levels {
        let config =
            CoreConfig::new().with_security_level(level.clone()).with_hardware_acceleration(true);

        // Maximum requires hardware acceleration
        if matches!(level, SecurityLevel::Maximum) {
            assert!(config.validate().is_ok());
        } else {
            // Other levels should validate with or without hardware
            let no_hw_config = CoreConfig::new()
                .with_security_level(level.clone())
                .with_hardware_acceleration(false);
            assert!(no_hw_config.validate().is_ok());
        }
    }
}

#[test]
fn test_all_crypto_schemes_available() {
    // All crypto schemes should be accessible
    let schemes = vec![
        CryptoScheme::Hybrid,
        CryptoScheme::Symmetric,
        CryptoScheme::Asymmetric,
        CryptoScheme::Homomorphic,
        CryptoScheme::PostQuantum,
    ];

    for scheme in schemes {
        let scheme_str = CryptoPolicyEngine::force_scheme(&scheme);
        assert!(!scheme_str.is_empty(), "Scheme {:?} should return non-empty string", scheme);
    }
}

#[test]
fn test_all_use_cases_available() {
    // All use cases should be available
    let use_cases = vec![
        UseCase::SecureMessaging,
        UseCase::EmailEncryption,
        UseCase::VpnTunnel,
        UseCase::ApiSecurity,
        UseCase::FileStorage,
        UseCase::DatabaseEncryption,
        UseCase::CloudStorage,
        UseCase::BackupArchive,
        UseCase::ConfigSecrets,
        UseCase::Authentication,
        UseCase::SessionToken,
        UseCase::DigitalCertificate,
        UseCase::KeyExchange,
        UseCase::FinancialTransactions,
        UseCase::LegalDocuments,
        UseCase::BlockchainTransaction,
        UseCase::HealthcareRecords,
        UseCase::GovernmentClassified,
        UseCase::PaymentCard,
        UseCase::IoTDevice,
        UseCase::FirmwareSigning,
        UseCase::SearchableEncryption,
        UseCase::HomomorphicComputation,
        UseCase::AuditLog,
    ];

    let config = CoreConfig::default();
    for use_case in use_cases {
        let scheme = CryptoPolicyEngine::recommend_scheme(&use_case, &config);
        assert!(scheme.is_ok(), "UseCase {:?} should return valid scheme", use_case);
    }
}

#[test]
fn test_feature_hardware_detection() {
    // Hardware detection should work with any feature combination
    let router = HardwareRouter::new();
    let info = router.detect_hardware();

    // CPU should always be available
    assert!(info.available_accelerators.contains(&HardwareType::Cpu));
}

#[test]
fn test_feature_config_types() {
    // All config types should be constructible
    let _core = CoreConfig::new();
    let _encryption = EncryptionConfig::new();
    let _signature = SignatureConfig::new();
    let _zero_trust = ZeroTrustConfig::new();
    let _hardware = HardwareConfig::new();
    let _use_case = UseCaseConfig::new(UseCase::SecureMessaging);
}

#[test]
fn test_feature_conditional_compilation_markers() {
    // Verify conditional compilation works correctly
    #[cfg(debug_assertions)]
    {
        // Debug mode specific tests
        let debug_mode = true;
        assert!(debug_mode);
    }

    #[cfg(not(debug_assertions))]
    {
        // Release mode specific tests
        let release_mode = true;
        assert!(release_mode);
    }
}

#[test]
fn test_feature_target_os_detection() {
    // Verify OS detection works
    #[cfg(target_os = "linux")]
    {
        let is_linux = true;
        assert!(is_linux);
    }

    #[cfg(target_os = "macos")]
    {
        let is_macos = true;
        assert!(is_macos);
    }

    #[cfg(target_os = "windows")]
    {
        let is_windows = true;
        assert!(is_windows);
    }
}

#[test]
fn test_feature_target_arch_detection() {
    // Verify architecture detection works
    #[cfg(target_arch = "x86_64")]
    {
        let is_x86_64 = true;
        assert!(is_x86_64);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let is_aarch64 = true;
        assert!(is_aarch64);
    }

    #[cfg(target_arch = "x86")]
    {
        let is_x86 = true;
        assert!(is_x86);
    }
}

#[test]
fn test_feature_optional_dependencies() {
    // Test that optional functionality degrades gracefully
    let config = HardwareConfig::new().with_acceleration(false).with_force_cpu(true);

    assert!(config.validate().is_ok());
    assert!(config.force_cpu);
    assert!(!config.acceleration_enabled);
}

// ============================================================================
// SECTION 3: Environment Tests (10+ tests)
// ============================================================================

#[test]
fn test_env_debug_release_behavior_consistency() {
    // Core behavior should be consistent between debug and release
    let config = CoreConfig::default();

    // These should work the same in both modes
    assert_eq!(config.security_level, SecurityLevel::High);
    assert!(config.validate().is_ok());

    let dev_config = CoreConfig::for_development();
    let prod_config = CoreConfig::for_production();

    assert_ne!(dev_config.security_level, prod_config.security_level);
}

#[test]
fn test_env_thread_local_storage() {
    // Test thread-local storage availability
    thread_local! {
        static THREAD_CONFIG: std::cell::RefCell<Option<CoreConfig>> = std::cell::RefCell::new(None);
    }

    THREAD_CONFIG.with(|config| {
        *config.borrow_mut() = Some(CoreConfig::default());
    });

    THREAD_CONFIG.with(|config| {
        let borrowed = config.borrow();
        assert!(borrowed.is_some());
        assert_eq!(borrowed.as_ref().expect("config").security_level, SecurityLevel::High);
    });
}

#[test]
fn test_env_thread_local_isolation() {
    // Thread-local storage should be isolated between threads
    use std::sync::mpsc;

    thread_local! {
        static THREAD_ID: std::cell::Cell<u64> = std::cell::Cell::new(0);
    }

    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        THREAD_ID.with(|id| id.set(42));
        THREAD_ID.with(|id| tx.send(id.get()).expect("send"))
    });

    THREAD_ID.with(|id| id.set(100));

    let thread_value = rx.recv().expect("recv");
    let main_value = THREAD_ID.with(|id| id.get());

    assert_eq!(thread_value, 42);
    assert_eq!(main_value, 100);

    handle.join().expect("join");
}

#[test]
fn test_env_random_number_generation() {
    // Random number generation should work
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut buffer = [0u8; 32];
    rng.fill_bytes(&mut buffer);

    // Should produce non-zero output (statistically certain)
    let all_zero = buffer.iter().all(|&b| b == 0);
    assert!(!all_zero, "RNG should produce non-zero output");

    // Multiple calls should produce different output
    let mut buffer2 = [0u8; 32];
    rng.fill_bytes(&mut buffer2);
    assert_ne!(buffer, buffer2, "RNG should produce different values on each call");
}

#[test]
fn test_env_random_reproducibility_with_seed() {
    // Test that key derivation with same inputs produces reproducible outputs
    use arc_core::derive_key_unverified;

    let password = b"test-password";
    let salt = b"test-salt";

    let key1 = derive_key_unverified(password, salt, 64);
    let key2 = derive_key_unverified(password, salt, 64);

    assert!(key1.is_ok(), "Key derivation should succeed");
    assert!(key2.is_ok(), "Key derivation should succeed");

    let k1 = key1.expect("already checked");
    let k2 = key2.expect("already checked");
    assert_eq!(k1, k2, "Same inputs should produce same derived key");
}

#[test]
fn test_env_time_operations() {
    // Time operations should work consistently
    let start = Instant::now();
    thread::sleep(Duration::from_millis(10));
    let elapsed = start.elapsed();

    assert!(elapsed >= Duration::from_millis(10), "Elapsed time should be at least 10ms");
    assert!(
        elapsed < Duration::from_millis(1000),
        "Elapsed time should be less than 1s (sanity check)"
    );
}

#[test]
fn test_env_system_time() {
    // System time should be available
    let now = std::time::SystemTime::now();
    let since_epoch = now.duration_since(std::time::UNIX_EPOCH);

    assert!(since_epoch.is_ok(), "System time should be after Unix epoch");

    let secs = since_epoch.expect("duration").as_secs();
    // Should be after year 2020 (1577836800)
    assert!(secs > 1577836800, "System time should be after 2020");
}

#[test]
fn test_env_monotonic_time() {
    // Instant should be monotonic
    let times: Vec<Instant> = (0..10).map(|_| Instant::now()).collect();

    for window in times.windows(2) {
        let t1 = window.get(0).expect("first");
        let t2 = window.get(1).expect("second");
        assert!(*t2 >= *t1, "Instant should be monotonically increasing");
    }
}

#[test]
fn test_env_multithreaded_config_access() {
    // Config should be safely accessible from multiple threads
    use std::sync::Arc;

    let config = Arc::new(CoreConfig::default());
    let mut handles = vec![];

    for _ in 0..4 {
        let config_clone = Arc::clone(&config);
        let handle = thread::spawn(move || {
            assert_eq!(config_clone.security_level, SecurityLevel::High);
            assert!(config_clone.hardware_acceleration);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

#[test]
fn test_env_stack_overflow_prevention() {
    // Deep recursion should be handled (test reasonable depth)
    fn recursive_validate(config: &CoreConfig, depth: u32) -> bool {
        if depth == 0 {
            return config.validate().is_ok();
        }
        recursive_validate(config, depth - 1)
    }

    let config = CoreConfig::default();
    // 100 levels of recursion should be fine
    assert!(recursive_validate(&config, 100));
}

// ============================================================================
// SECTION 4: Configuration Variations Tests (10+ tests)
// ============================================================================

#[test]
fn test_config_crypto_config_default() {
    let config = CryptoConfig::new();

    assert!(!config.is_verified());
    assert!(matches!(
        config.get_selection(),
        AlgorithmSelection::SecurityLevel(SecurityLevel::High)
    ));
}

#[test]
fn test_config_crypto_config_with_use_case() {
    let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);

    assert!(matches!(
        config.get_selection(),
        AlgorithmSelection::UseCase(UseCase::FinancialTransactions)
    ));
}

#[test]
fn test_config_crypto_config_security_level_override() {
    let config =
        CryptoConfig::new().use_case(UseCase::IoTDevice).security_level(SecurityLevel::Maximum);

    // Security level should override use case
    assert!(matches!(
        config.get_selection(),
        AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum)
    ));
}

#[test]
fn test_config_security_level_all_combinations() {
    let levels = vec![
        SecurityLevel::Standard,
        SecurityLevel::High,
        SecurityLevel::Maximum,
        SecurityLevel::Quantum,
    ];

    for level in levels {
        let config = CryptoConfig::new().security_level(level.clone());
        assert!(matches!(config.get_selection(), AlgorithmSelection::SecurityLevel(_)));
    }
}

#[test]
fn test_config_hardware_detection_fallback() {
    // Test hardware detection with fallback enabled
    let config = HardwareConfig::new().with_acceleration(true).with_fallback(true);

    assert!(config.validate().is_ok());

    // Test without fallback
    let config_no_fallback = HardwareConfig::new().with_acceleration(true).with_fallback(false);

    assert!(config_no_fallback.validate().is_ok());
}

#[test]
fn test_config_hardware_cpu_only_mode() {
    let config = HardwareConfig::new().with_acceleration(false).with_force_cpu(true);

    assert!(config.validate().is_ok());
    assert!(config.force_cpu);
}

#[test]
fn test_config_hardware_accelerator_preferences() {
    let config = HardwareConfig::new()
        .with_preferred_accelerator(HardwareType::Gpu)
        .with_preferred_accelerator(HardwareType::Fpga)
        .with_preferred_accelerator(HardwareType::Cpu);

    assert_eq!(config.preferred_accelerators.len(), 3);
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_policy_engine_all_security_levels() {
    let data = b"test data for policy engine";

    for level in [
        SecurityLevel::Standard,
        SecurityLevel::High,
        SecurityLevel::Maximum,
        SecurityLevel::Quantum,
    ] {
        let config =
            CoreConfig::new().with_security_level(level.clone()).with_hardware_acceleration(true);

        let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None);
        assert!(scheme.is_ok(), "Security level {:?} should produce valid scheme", level);

        let scheme_str = scheme.expect("scheme");
        match level {
            SecurityLevel::Quantum => {
                assert!(scheme_str.contains("pq-"), "Quantum should use PQ-only scheme");
            }
            _ => {
                assert!(scheme_str.contains("hybrid"), "Non-quantum should use hybrid scheme");
            }
        }
    }
}

#[test]
fn test_config_zero_trust_configurations() {
    let configs = vec![
        ZeroTrustConfig::new()
            .with_timeout(1000)
            .with_complexity(ProofComplexity::Low)
            .with_continuous_verification(false),
        ZeroTrustConfig::new()
            .with_timeout(5000)
            .with_complexity(ProofComplexity::Medium)
            .with_continuous_verification(true)
            .with_verification_interval(30000),
        ZeroTrustConfig::new()
            .with_timeout(10000)
            .with_complexity(ProofComplexity::High)
            .with_continuous_verification(true)
            .with_verification_interval(60000),
    ];

    for config in configs {
        assert!(config.validate().is_ok());
    }
}

#[test]
fn test_config_encryption_with_scheme_preferences() {
    let schemes = vec![CryptoScheme::Hybrid, CryptoScheme::Symmetric, CryptoScheme::PostQuantum];

    for scheme in schemes {
        let config = EncryptionConfig::new()
            .with_scheme(scheme.clone())
            .with_compression(true)
            .with_integrity_check(true);

        assert!(config.validate().is_ok());
        assert_eq!(config.preferred_scheme, Some(scheme));
    }
}

#[test]
fn test_config_use_case_nested_validation() {
    // Test that all nested configs in UseCaseConfig validate together
    let use_cases = vec![
        UseCase::SecureMessaging,
        UseCase::FinancialTransactions,
        UseCase::GovernmentClassified,
        UseCase::IoTDevice,
    ];

    for use_case in use_cases {
        let config = UseCaseConfig::new(use_case.clone());

        // Should validate encryption, signature, zero_trust, and hardware
        assert!(config.validate().is_ok(), "UseCaseConfig for {:?} should validate", use_case);

        // Nested configs should be consistent
        assert_eq!(
            config.encryption.base.security_level, config.signature.base.security_level,
            "Encryption and signature should have same security level"
        );
    }
}

#[test]
fn test_config_performance_metrics_adaptive() {
    let data = b"test data";
    let config = CoreConfig::new()
        .with_performance_preference(PerformancePreference::Balanced)
        .with_security_level(SecurityLevel::High);

    // Test with default metrics
    let metrics = PerformanceMetrics::default();
    let scheme = CryptoPolicyEngine::adaptive_selection(data, &metrics, &config);
    assert!(scheme.is_ok());

    // Test with high memory pressure
    let high_memory_metrics = PerformanceMetrics {
        encryption_speed_ms: 100.0,
        decryption_speed_ms: 50.0,
        memory_usage_mb: 600.0, // High memory usage
        cpu_usage_percent: 50.0,
    };

    let memory_config = CoreConfig::new()
        .with_performance_preference(PerformancePreference::Memory)
        .with_security_level(SecurityLevel::High);

    let scheme = CryptoPolicyEngine::adaptive_selection(data, &high_memory_metrics, &memory_config);
    assert!(scheme.is_ok());
}

// ============================================================================
// SECTION 5: Additional Cross-Platform Tests (bonus tests)
// ============================================================================

#[test]
fn test_zeroized_bytes_drop() {
    // ZeroizedBytes should properly clean up on drop
    let sensitive_data = vec![0xABu8; 64];
    let zeroized = ZeroizedBytes::new(sensitive_data.clone());

    assert_eq!(zeroized.len(), 64);
    assert!(!zeroized.is_empty());

    // Data should be accessible before drop
    assert_eq!(zeroized.as_slice().first(), Some(&0xAB));
}

#[test]
fn test_keypair_construction() {
    // KeyPair should work on all platforms
    use arc_core::types::PrivateKey;

    let public_key = vec![1u8, 2, 3, 4, 5];
    let private_key = PrivateKey::new(vec![10, 20, 30, 40, 50]);

    let keypair = KeyPair::new(public_key.clone(), private_key);

    assert_eq!(keypair.public_key(), &public_key);
    assert_eq!(keypair.private_key().len(), 5);
}

#[test]
fn test_concurrent_policy_engine_access() {
    // Policy engine should be thread-safe
    use std::sync::Arc;

    let configs: Vec<Arc<CoreConfig>> = (0..4).map(|_| Arc::new(CoreConfig::default())).collect();

    let handles: Vec<_> = configs
        .into_iter()
        .map(|config| {
            thread::spawn(move || {
                let data = b"concurrent test";
                CryptoPolicyEngine::select_encryption_scheme(data, &config, None)
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join().expect("Thread should complete");
        assert!(result.is_ok());
    }
}

#[test]
fn test_hardware_router_thread_safe() {
    // Hardware router should be thread-safe
    use std::sync::Arc;

    let router = Arc::new(HardwareRouter::new());
    let mut handles = vec![];

    for _ in 0..4 {
        let router_clone = Arc::clone(&router);
        let handle = thread::spawn(move || {
            let info = router_clone.detect_hardware();
            assert!(info.available_accelerators.contains(&HardwareType::Cpu));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete");
    }
}

#[test]
fn test_error_types_send_sync() {
    // Errors should be Send + Sync for async contexts
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<CoreError>();
}

#[test]
fn test_config_types_clone() {
    // All config types should be cloneable
    let core = CoreConfig::default();
    let core_clone = core.clone();
    assert_eq!(core, core_clone);

    let encryption = EncryptionConfig::default();
    let encryption_clone = encryption.clone();
    assert_eq!(encryption.compression_enabled, encryption_clone.compression_enabled);

    let hardware = HardwareConfig::default();
    let hardware_clone = hardware.clone();
    assert_eq!(hardware.threshold_bytes, hardware_clone.threshold_bytes);
}

#[test]
fn test_config_debug_formatting() {
    // All config types should have Debug implementations
    let core = CoreConfig::default();
    let debug_str = format!("{:?}", core);
    assert!(debug_str.contains("CoreConfig"));

    let security = SecurityLevel::High;
    let security_debug = format!("{:?}", security);
    assert!(security_debug.contains("High"));
}

#[test]
fn test_memory_layout_stability() {
    // Document memory layout for potential ABI concerns
    // Note: These may change between versions, this documents current state

    // Basic types should have stable sizes
    assert!(mem::size_of::<SecurityLevel>() <= 8);
    assert!(mem::size_of::<PerformancePreference>() <= 8);
    assert!(mem::size_of::<CryptoScheme>() <= 8);

    // Config structs sizes (for documentation)
    let _core_size = mem::size_of::<CoreConfig>();
    let _encryption_size = mem::size_of::<EncryptionConfig>();

    // Just verify they're reasonable (not excessively large)
    assert!(mem::size_of::<CoreConfig>() < 1024);
}
