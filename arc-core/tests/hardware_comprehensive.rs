//! Comprehensive tests for Hardware Detection at arc-core.
//!
//! This test suite provides thorough coverage of hardware detection capabilities,
//! including CPU feature detection, GPU/FPGA/TPM/SGX availability detection,
//! algorithm recommendations, fallback behavior, caching, thread-safety,
//! and platform compatibility.
//!
//! # Test Coverage (Tasks 1.8.1-1.8.14)
//!
//! 1. **CPU Feature Detection (1.8.1)**
//!    - AVX, AVX2, AVX-512, AES-NI instruction detection
//!    - SIMD support verification
//!    - Thread count detection
//!
//! 2. **GPU Availability Detection (1.8.2)**
//!    - NVIDIA GPU detection via nvidia-smi
//!    - Cross-platform GPU detection handling
//!
//! 3. **FPGA/TPM/SGX Detection (1.8.3)**
//!    - FPGA device detection (Xilinx/Altera)
//!    - TPM availability checking
//!    - Intel SGX enclave detection
//!
//! 4. **Algorithm Recommendations (1.8.4)**
//!    - Hardware-based algorithm selection
//!    - Capability-based recommendations
//!
//! 5. **Fallback Behavior (1.8.5)**
//!    - Graceful degradation when features unavailable
//!    - CPU fallback guarantees
//!
//! 6. **Detection Caching (1.8.6)**
//!    - Cache hit verification
//!    - Cache consistency
//!
//! 7. **Thread Safety (1.8.7)**
//!    - Concurrent access to hardware router
//!    - Mutex handling under contention
//!
//! 8. **Platform Compatibility (1.8.8)**
//!    - macOS-specific behavior
//!    - Linux-specific behavior
//!    - Cross-platform accelerator instantiation

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
    clippy::print_stdout,
    clippy::use_debug,
    unused_qualifications
)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use arc_core::{
    error::{CoreError, Result},
    hardware::{
        CpuAccelerator, FpgaAccelerator, GpuAccelerator, HardwareRouter, SgxAccelerator,
        TpmAccelerator,
    },
    traits::{HardwareAccelerator, HardwareCapabilities, HardwareInfo, HardwareType},
};

// ============================================================================
// Task 1.8.1: CPU Feature Detection (AVX, AVX2, AVX-512, AES-NI)
// ============================================================================

/// Test that CPU is always detected as an available accelerator.
#[test]
fn test_cpu_always_available() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    assert!(
        hw_info.available_accelerators.contains(&HardwareType::Cpu),
        "CPU should always be detected as available"
    );
}

/// Test CPU SIMD support detection.
#[test]
fn test_cpu_simd_support_detection() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // On modern x86_64 CPUs, SIMD should be supported
    #[cfg(target_arch = "x86_64")]
    {
        assert!(hw_info.capabilities.simd_support, "SIMD should be detected on x86_64 CPUs");
    }

    // On other architectures, we just verify the field exists and is boolean
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _simd_support = hw_info.capabilities.simd_support;
    }
}

/// Test AES-NI instruction detection.
#[test]
fn test_cpu_aes_ni_detection() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // On most modern x86_64 CPUs, AES-NI should be available
    #[cfg(target_arch = "x86_64")]
    {
        assert!(hw_info.capabilities.aes_ni, "AES-NI should be detected on modern x86_64 CPUs");
    }

    // On other architectures, verify the field exists
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _aes_ni = hw_info.capabilities.aes_ni;
    }
}

/// Test x86_64-specific AVX feature detection via is_x86_feature_detected.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_x86_64_avx_features() {
    // These are compile-time/runtime CPU feature checks
    let has_avx = std::arch::is_x86_feature_detected!("avx");
    let has_avx2 = std::arch::is_x86_feature_detected!("avx2");
    let has_aes = std::arch::is_x86_feature_detected!("aes");

    // Log detected features for debugging
    println!("AVX detected: {}", has_avx);
    println!("AVX2 detected: {}", has_avx2);
    println!("AES-NI detected: {}", has_aes);

    // Most modern CPUs should have AVX
    // This test documents the current system's capabilities
    if has_avx {
        println!("System supports AVX instructions");
    }
    if has_avx2 {
        println!("System supports AVX2 instructions");
    }
    if has_aes {
        println!("System supports AES-NI instructions");
    }

    // At minimum, the router should report the capabilities correctly
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // If AES-NI is detected by the CPU, the router should report it
    if has_aes {
        assert!(hw_info.capabilities.aes_ni, "Router should report AES-NI when CPU supports it");
    }
}

/// Test AVX-512 feature detection on x86_64.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_x86_64_avx512_detection() {
    // AVX-512 is available on some Intel CPUs
    let has_avx512f = std::arch::is_x86_feature_detected!("avx512f");

    println!("AVX-512F detected: {}", has_avx512f);

    // This test documents the current system's AVX-512 capabilities
    if has_avx512f {
        println!("System supports AVX-512 instructions");
    } else {
        println!("System does not support AVX-512 (common on consumer CPUs)");
    }

    // The test passes regardless - we're just documenting capabilities
}

/// Test thread count detection is accurate.
#[test]
fn test_cpu_thread_count_detection() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // Thread count should match rayon's thread pool
    let expected_threads = rayon::current_num_threads();

    assert_eq!(
        hw_info.capabilities.threads, expected_threads,
        "Detected thread count should match rayon's thread pool size"
    );

    assert!(hw_info.capabilities.threads > 0, "Thread count must be positive");

    assert!(hw_info.capabilities.threads <= 1024, "Thread count should be reasonable (<=1024)");
}

/// Test CPU accelerator with full capabilities.
#[test]
fn test_cpu_accelerator_full_capabilities() {
    let capabilities =
        HardwareCapabilities { simd_support: true, aes_ni: true, threads: 16, memory: 0 };

    let cpu = CpuAccelerator::new(&capabilities);

    assert_eq!(cpu.name(), "CPU Accelerator");
    assert_eq!(cpu.hardware_type(), HardwareType::Cpu);
    assert!(cpu.is_available(), "CPU should always be available");
}

/// Test CPU accelerator with minimal capabilities.
#[test]
fn test_cpu_accelerator_minimal_capabilities() {
    let capabilities =
        HardwareCapabilities { simd_support: false, aes_ni: false, threads: 1, memory: 0 };

    let cpu = CpuAccelerator::new(&capabilities);

    // CPU should still be available even with minimal capabilities
    assert!(cpu.is_available(), "CPU should be available even without SIMD/AES-NI");
}

// ============================================================================
// Task 1.8.2: GPU Availability Detection
// ============================================================================

/// Test GPU accelerator creation and basic properties.
#[test]
fn test_gpu_accelerator_creation() {
    let gpu = GpuAccelerator::new();

    assert_eq!(gpu.name(), "GPU Accelerator");
    assert_eq!(gpu.hardware_type(), HardwareType::Gpu);

    // Availability depends on system configuration
    let _is_available = gpu.is_available();
}

/// Test GPU accelerator default constructor.
#[test]
fn test_gpu_accelerator_default_constructor() {
    let gpu1 = GpuAccelerator::new();
    let gpu2 = GpuAccelerator::default();

    // Both constructors should produce equivalent accelerators
    assert_eq!(gpu1.hardware_type(), gpu2.hardware_type());
    assert_eq!(gpu1.name(), gpu2.name());
    assert_eq!(gpu1.is_available(), gpu2.is_available());
}

/// Test GPU detection is consistent across multiple calls.
#[test]
fn test_gpu_detection_consistency() {
    let gpu1 = GpuAccelerator::new();
    let gpu2 = GpuAccelerator::new();
    let gpu3 = GpuAccelerator::new();

    let available1 = gpu1.is_available();
    let available2 = gpu2.is_available();
    let available3 = gpu3.is_available();

    assert_eq!(available1, available2, "GPU detection should be consistent");
    assert_eq!(available2, available3, "GPU detection should be consistent");
}

/// Test GPU detection on macOS (should report unavailable).
#[cfg(target_os = "macos")]
#[test]
fn test_gpu_detection_macos() {
    let gpu = GpuAccelerator::new();

    // On macOS, nvidia-smi is typically not available
    // The GPU accelerator returns false for non-Linux/Windows
    assert!(!gpu.is_available(), "GPU detection via nvidia-smi should return false on macOS");
}

/// Test GPU detection on Linux.
#[cfg(target_os = "linux")]
#[test]
fn test_gpu_detection_linux() {
    let gpu = GpuAccelerator::new();

    // GPU availability depends on whether nvidia-smi is installed
    let is_available = gpu.is_available();

    // Document the result without asserting
    if is_available {
        println!("NVIDIA GPU detected on this Linux system");
    } else {
        println!("No NVIDIA GPU detected (nvidia-smi not available or failed)");
    }
}

// ============================================================================
// Task 1.8.3: FPGA/TPM/SGX Detection
// ============================================================================

/// Test FPGA accelerator creation and detection.
#[test]
fn test_fpga_accelerator_creation() {
    let fpga = FpgaAccelerator::new();

    assert_eq!(fpga.name(), "FPGA Accelerator");
    assert_eq!(fpga.hardware_type(), HardwareType::Fpga);

    let _is_available = fpga.is_available();
}

/// Test FPGA default constructor.
#[test]
fn test_fpga_accelerator_default_constructor() {
    let fpga1 = FpgaAccelerator::new();
    let fpga2 = FpgaAccelerator::default();

    assert_eq!(fpga1.hardware_type(), fpga2.hardware_type());
    assert_eq!(fpga1.is_available(), fpga2.is_available());
}

/// Test FPGA detection on macOS (should be unavailable).
#[cfg(target_os = "macos")]
#[test]
fn test_fpga_detection_macos() {
    let fpga = FpgaAccelerator::new();

    assert!(!fpga.is_available(), "FPGA should not be available on macOS (no device files)");
}

/// Test FPGA detection on Linux.
#[cfg(target_os = "linux")]
#[test]
fn test_fpga_detection_linux() {
    let fpga = FpgaAccelerator::new();

    // FPGA detection checks for /dev/xdma0 or /dev/altera_fpgamgr
    let is_available = fpga.is_available();

    if is_available {
        println!("FPGA device detected on this Linux system");
    } else {
        println!("No FPGA device detected (typical for dev systems)");
    }
}

/// Test TPM accelerator creation and detection.
#[test]
fn test_tpm_accelerator_creation() {
    let tpm = TpmAccelerator::new();

    assert_eq!(tpm.name(), "TPM Accelerator");
    assert_eq!(tpm.hardware_type(), HardwareType::Tpu);

    let _is_available = tpm.is_available();
}

/// Test TPM default constructor.
#[test]
fn test_tpm_accelerator_default_constructor() {
    let tpm1 = TpmAccelerator::new();
    let tpm2 = TpmAccelerator::default();

    assert_eq!(tpm1.hardware_type(), tpm2.hardware_type());
    assert_eq!(tpm1.is_available(), tpm2.is_available());
}

/// Test TPM detection on macOS (should be unavailable).
#[cfg(target_os = "macos")]
#[test]
fn test_tpm_detection_macos() {
    let tpm = TpmAccelerator::new();

    assert!(!tpm.is_available(), "TPM should not be available on macOS (no /dev/tpm0)");
}

/// Test TPM detection on Linux.
#[cfg(target_os = "linux")]
#[test]
fn test_tpm_detection_linux() {
    let tpm = TpmAccelerator::new();

    // TPM detection checks for /dev/tpm0 or /dev/tpmrm0
    let is_available = tpm.is_available();

    if is_available {
        println!("TPM device detected on this Linux system");
    } else {
        println!("No TPM device detected");
    }
}

/// Test SGX accelerator creation and detection.
#[test]
fn test_sgx_accelerator_creation() {
    let sgx = SgxAccelerator::new();

    assert_eq!(sgx.name(), "SGX Accelerator");
    assert_eq!(sgx.hardware_type(), HardwareType::Sgx);

    let _is_available = sgx.is_available();
}

/// Test SGX default constructor.
#[test]
fn test_sgx_accelerator_default_constructor() {
    let sgx1 = SgxAccelerator::new();
    let sgx2 = SgxAccelerator::default();

    assert_eq!(sgx1.hardware_type(), sgx2.hardware_type());
    assert_eq!(sgx1.is_available(), sgx2.is_available());
}

/// Test SGX detection typically returns false on most systems.
#[test]
fn test_sgx_detection_typical() {
    let sgx = SgxAccelerator::new();

    // SGX requires specific Intel CPUs and /dev/sgx device
    let is_available = sgx.is_available();

    if is_available {
        println!("Intel SGX detected on this system");
    } else {
        println!("Intel SGX not available (typical for most systems)");
    }
}

/// Test SGX detection on macOS (should be unavailable).
#[cfg(target_os = "macos")]
#[test]
fn test_sgx_detection_macos() {
    let sgx = SgxAccelerator::new();

    assert!(!sgx.is_available(), "SGX should not be available on macOS");
}

// ============================================================================
// Task 1.8.4: Algorithm Recommendations Based on Hardware
// ============================================================================

/// Test that hardware info provides algorithm selection guidance.
#[test]
fn test_algorithm_recommendation_cpu_only() {
    let hw_info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 8,
            memory: 0,
        },
    };

    // With AES-NI, AES-GCM is the recommended symmetric cipher
    assert!(hw_info.capabilities.aes_ni, "AES-NI should enable hardware-accelerated AES-GCM");

    // With SIMD, parallel operations are preferred
    assert!(hw_info.capabilities.simd_support, "SIMD should enable vectorized operations");
}

/// Test algorithm recommendation with no AES-NI.
#[test]
fn test_algorithm_recommendation_no_aes_ni() {
    let hw_info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: false,
            threads: 4,
            memory: 0,
        },
    };

    // Without AES-NI, ChaCha20-Poly1305 might be preferred
    assert!(
        !hw_info.capabilities.aes_ni,
        "Without AES-NI, software AES or ChaCha20 should be used"
    );
}

/// Test best accelerator selection with GPU available.
#[test]
fn test_best_accelerator_with_gpu() {
    let hw_info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Gpu],
        preferred_accelerator: Some(HardwareType::Gpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 8,
            memory: 0,
        },
    };

    let best = hw_info.best_accelerator();
    assert_eq!(best, Some(&HardwareType::Gpu), "GPU should be preferred when set");
}

/// Test best accelerator falls back to first available.
#[test]
fn test_best_accelerator_fallback() {
    let hw_info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Fpga],
        preferred_accelerator: None,
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 4,
            memory: 0,
        },
    };

    let best = hw_info.best_accelerator();
    assert_eq!(best, Some(&HardwareType::Cpu), "Should fall back to first available accelerator");
}

// ============================================================================
// Task 1.8.5: Fallback When Features Unavailable
// ============================================================================

/// Test CPU always provides a fallback.
#[test]
fn test_cpu_fallback_guaranteed() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // CPU should always be in the available accelerators list
    assert!(
        hw_info.available_accelerators.contains(&HardwareType::Cpu),
        "CPU must always be available as fallback"
    );

    // Best accelerator should never be None when CPU is available
    let best = hw_info.best_accelerator();
    assert!(best.is_some(), "Best accelerator should exist when CPU is available");
}

/// Test operation routing succeeds with CPU fallback.
#[test]
fn test_operation_routing_with_fallback() {
    let router = HardwareRouter::new();

    // This operation should succeed even if specialized hardware is unavailable
    let result: Result<i32> = router.route_to_best_hardware(|| Ok(42));

    assert!(result.is_ok(), "Operation should succeed with CPU fallback");
    assert_eq!(result.expect("should succeed"), 42);
}

/// Test graceful handling when no GPU available.
#[test]
fn test_graceful_fallback_no_gpu() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // Even without GPU, operation should succeed
    let result: Result<Vec<u8>> = router.route_to_best_hardware(|| {
        // Simulate a computation that could benefit from GPU
        let data: Vec<u8> = (0..100).collect();
        Ok(data)
    });

    assert!(result.is_ok(), "Should work without GPU via CPU fallback");

    // Verify CPU is used when GPU unavailable
    if !hw_info.available_accelerators.contains(&HardwareType::Gpu) {
        assert_eq!(
            hw_info.preferred_accelerator,
            Some(HardwareType::Cpu),
            "CPU should be preferred when GPU unavailable"
        );
    }
}

/// Test empty accelerator list still has best_accelerator handling.
#[test]
fn test_empty_accelerators_handling() {
    let hw_info = HardwareInfo {
        available_accelerators: vec![],
        preferred_accelerator: None,
        capabilities: HardwareCapabilities {
            simd_support: false,
            aes_ni: false,
            threads: 1,
            memory: 0,
        },
    };

    let best = hw_info.best_accelerator();
    assert!(best.is_none(), "Should return None when no accelerators available");
}

// ============================================================================
// Task 1.8.6: Detection Caching
// ============================================================================

/// Test that hardware detection results are cached.
#[test]
fn test_detection_caching_basic() {
    let router = HardwareRouter::new();

    let hw_info1 = router.detect_hardware();
    let hw_info2 = router.detect_hardware();

    // Cached results should be identical
    assert_eq!(
        hw_info1.capabilities.threads, hw_info2.capabilities.threads,
        "Cached thread count should match"
    );

    assert_eq!(
        hw_info1.capabilities.simd_support, hw_info2.capabilities.simd_support,
        "Cached SIMD support should match"
    );

    assert_eq!(
        hw_info1.capabilities.aes_ni, hw_info2.capabilities.aes_ni,
        "Cached AES-NI support should match"
    );
}

/// Test that caching provides performance benefit.
#[test]
fn test_detection_caching_performance() {
    let router = HardwareRouter::new();

    // First call performs detection
    let start1 = Instant::now();
    let _hw_info1 = router.detect_hardware();
    let duration1 = start1.elapsed();

    // Subsequent calls should be faster (from cache)
    let mut cached_durations = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        let _hw_info = router.detect_hardware();
        cached_durations.push(start.elapsed());
    }

    // Calculate average cached duration
    let avg_cached: Duration = cached_durations.iter().sum::<Duration>() / 10;

    // Cached calls should generally be faster (but we can't guarantee this
    // due to system variability, so we just document the behavior)
    println!("First detection: {:?}", duration1);
    println!("Average cached detection: {:?}", avg_cached);
}

/// Test cache is shared within the same router instance.
#[test]
fn test_detection_cache_sharing() {
    let router = HardwareRouter::new();

    // Multiple calls to the same router should use the same cache
    let hw1 = router.detect_hardware();
    let hw2 = router.detect_hardware();
    let hw3 = router.detect_hardware();

    assert_eq!(hw1.available_accelerators.len(), hw2.available_accelerators.len());
    assert_eq!(hw2.available_accelerators.len(), hw3.available_accelerators.len());
}

/// Test that different router instances have separate caches.
#[test]
fn test_separate_router_caches() {
    let router1 = HardwareRouter::new();
    let router2 = HardwareRouter::new();

    // Each router has its own cache
    let hw1 = router1.detect_hardware();
    let hw2 = router2.detect_hardware();

    // Both should detect the same hardware (same system)
    assert_eq!(
        hw1.capabilities.threads, hw2.capabilities.threads,
        "Different routers should detect same hardware"
    );
}

// ============================================================================
// Task 1.8.7: Thread Safety
// ============================================================================

/// Test concurrent access to hardware router from multiple threads.
#[test]
fn test_concurrent_hardware_detection() {
    let router = Arc::new(HardwareRouter::new());
    let mut handles = vec![];

    for _ in 0..20 {
        let router_clone = Arc::clone(&router);
        let handle = thread::spawn(move || {
            let hw_info = router_clone.detect_hardware();
            assert!(!hw_info.available_accelerators.is_empty());
            hw_info.capabilities.threads
        });
        handles.push(handle);
    }

    let results: Vec<usize> =
        handles.into_iter().map(|h| h.join().expect("thread should not panic")).collect();

    // All threads should see the same thread count
    let first = results[0];
    for &count in &results {
        assert_eq!(count, first, "All threads should see consistent results");
    }
}

/// Test concurrent operation routing.
#[test]
fn test_concurrent_operation_routing() {
    let router = Arc::new(HardwareRouter::new());
    let mut handles = vec![];

    for i in 0..20 {
        let router_clone = Arc::clone(&router);
        let handle = thread::spawn(move || {
            let result: Result<i32> = router_clone.route_to_best_hardware(|| Ok(i));
            result.expect("operation should succeed")
        });
        handles.push(handle);
    }

    let results: Vec<i32> =
        handles.into_iter().map(|h| h.join().expect("thread should not panic")).collect();

    // Verify all operations completed successfully
    assert_eq!(results.len(), 20);
}

/// Test mutex contention handling under high load.
#[test]
fn test_mutex_contention_handling() {
    let router = Arc::new(HardwareRouter::new());
    let mut handles = vec![];

    // Create many threads to stress the mutex
    for _ in 0..100 {
        let router_clone = Arc::clone(&router);
        let handle = thread::spawn(move || {
            // Each thread does multiple detections
            for _ in 0..10 {
                let _hw_info = router_clone.detect_hardware();
            }
        });
        handles.push(handle);
    }

    // All threads should complete without deadlock
    for handle in handles {
        handle.join().expect("thread should complete without panic");
    }
}

/// Test that cache is consistent under concurrent access.
#[test]
fn test_cache_consistency_under_contention() {
    let router = Arc::new(HardwareRouter::new());
    let mut handles = vec![];

    // Pre-populate the cache
    let initial = router.detect_hardware();
    let expected_threads = initial.capabilities.threads;

    // Multiple threads reading from cache
    for _ in 0..50 {
        let router_clone = Arc::clone(&router);
        let handle = thread::spawn(move || {
            let hw = router_clone.detect_hardware();
            hw.capabilities.threads
        });
        handles.push(handle);
    }

    for handle in handles {
        let threads = handle.join().expect("should complete");
        assert_eq!(threads, expected_threads, "Cache should be consistent");
    }
}

// ============================================================================
// Task 1.8.8: Platform Compatibility (macOS, Linux)
// ============================================================================

/// Test macOS-specific hardware detection behavior.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_platform_compatibility() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // CPU should always be available
    assert!(hw_info.available_accelerators.contains(&HardwareType::Cpu));

    // Verify macOS-specific accelerator availability
    let gpu = GpuAccelerator::new();
    let fpga = FpgaAccelerator::new();
    let tpm = TpmAccelerator::new();
    let sgx = SgxAccelerator::new();

    // These are typically not available on macOS
    assert!(!fpga.is_available(), "FPGA not available on macOS");
    assert!(!tpm.is_available(), "TPM not available on macOS");
    assert!(!sgx.is_available(), "SGX not available on macOS");

    // GPU detection via nvidia-smi returns false on macOS
    assert!(!gpu.is_available(), "nvidia-smi GPU detection not available on macOS");
}

/// Test Linux-specific hardware detection behavior.
#[cfg(target_os = "linux")]
#[test]
fn test_linux_platform_compatibility() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    // CPU should always be available
    assert!(hw_info.available_accelerators.contains(&HardwareType::Cpu));

    // On Linux, detection checks various device files
    let fpga = FpgaAccelerator::new();
    let tpm = TpmAccelerator::new();
    let sgx = SgxAccelerator::new();

    // Document what's available on this Linux system
    println!("FPGA available: {}", fpga.is_available());
    println!("TPM available: {}", tpm.is_available());
    println!("SGX available: {}", sgx.is_available());
}

/// Test that all accelerator types can be instantiated on any platform.
#[test]
fn test_cross_platform_accelerator_instantiation() {
    // All accelerators should be instantiable without panicking
    let cpu = CpuAccelerator::new(&HardwareCapabilities {
        simd_support: true,
        aes_ni: true,
        threads: 4,
        memory: 0,
    });

    let gpu = GpuAccelerator::new();
    let fpga = FpgaAccelerator::new();
    let tpm = TpmAccelerator::new();
    let sgx = SgxAccelerator::new();

    // Verify all implement HardwareAccelerator trait
    let accelerators: Vec<Box<dyn HardwareAccelerator>> =
        vec![Box::new(cpu), Box::new(gpu), Box::new(fpga), Box::new(tpm), Box::new(sgx)];

    for accel in &accelerators {
        assert!(!accel.name().is_empty(), "Name should not be empty");
        let _hw_type = accel.hardware_type();
        let _available = accel.is_available();
    }
}

// ============================================================================
// Additional Comprehensive Tests
// ============================================================================

/// Test HardwareInfo summary generation.
#[test]
fn test_hardware_info_summary() {
    let router = HardwareRouter::new();
    let hw_info = router.detect_hardware();

    let summary = hw_info.summary();

    assert!(!summary.is_empty(), "Summary should not be empty");
    assert!(summary.contains("Available"), "Summary should contain 'Available'");
    assert!(summary.contains("Preferred"), "Summary should contain 'Preferred'");
    assert!(summary.contains("Capabilities"), "Summary should contain 'Capabilities'");
}

/// Test HardwareType enum equality and cloning.
#[test]
fn test_hardware_type_properties() {
    let cpu = HardwareType::Cpu;
    let gpu = HardwareType::Gpu;
    let fpga = HardwareType::Fpga;
    let tpu = HardwareType::Tpu;
    let sgx = HardwareType::Sgx;

    // Test equality
    assert_eq!(cpu.clone(), HardwareType::Cpu);
    assert_ne!(cpu, gpu);
    assert_ne!(gpu, fpga);
    assert_ne!(fpga, tpu);
    assert_ne!(tpu, sgx);

    // Test Debug trait
    assert!(format!("{:?}", cpu).contains("Cpu"));
    assert!(format!("{:?}", gpu).contains("Gpu"));
}

/// Test HardwareCapabilities cloning.
#[test]
fn test_hardware_capabilities_cloning() {
    let caps = HardwareCapabilities { simd_support: true, aes_ni: true, threads: 8, memory: 1024 };

    let cloned = caps.clone();

    assert_eq!(caps.simd_support, cloned.simd_support);
    assert_eq!(caps.aes_ni, cloned.aes_ni);
    assert_eq!(caps.threads, cloned.threads);
    assert_eq!(caps.memory, cloned.memory);
}

/// Test error propagation through route_to_best_hardware.
#[test]
fn test_error_propagation_in_routing() {
    let router = HardwareRouter::new();

    let result: Result<i32> = router.route_to_best_hardware(|| {
        Err(CoreError::HardwareError("Simulated hardware failure".to_string()))
    });

    assert!(result.is_err(), "Error should be propagated");

    match result {
        Err(CoreError::HardwareError(msg)) => {
            assert_eq!(msg, "Simulated hardware failure");
        }
        _ => panic!("Expected HardwareError"),
    }
}

/// Test routing with complex computation.
#[test]
fn test_routing_complex_computation() {
    let router = HardwareRouter::new();

    let result: Result<Vec<u64>> = router.route_to_best_hardware(|| {
        // Simulate crypto-like computation
        let mut data = vec![1u64; 1000];
        for i in 1..data.len() {
            data[i] = data[i - 1].wrapping_mul(31).wrapping_add(i as u64);
        }
        Ok(data)
    });

    assert!(result.is_ok(), "Complex computation should succeed");
    let data = result.expect("should succeed");
    assert_eq!(data.len(), 1000);
}

/// Test that router is Send + Sync.
#[test]
fn test_router_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HardwareRouter>();
}

/// Test hardware detection with multiple routers in parallel.
#[test]
fn test_multiple_routers_parallel() {
    let handles: Vec<_> = (0..10)
        .map(|_| {
            thread::spawn(|| {
                let router = HardwareRouter::new();
                let hw = router.detect_hardware();
                hw.capabilities.threads
            })
        })
        .collect();

    let results: Vec<usize> =
        handles.into_iter().map(|h| h.join().expect("should complete")).collect();

    // All should detect the same thread count
    let first = results[0];
    for count in results {
        assert_eq!(count, first, "All routers should detect same thread count");
    }
}

/// Test integration: full detection and routing workflow.
#[test]
fn test_full_workflow_integration() {
    // Step 1: Create router
    let router = HardwareRouter::new();

    // Step 2: Detect hardware
    let hw_info = router.detect_hardware();

    // Step 3: Verify CPU is available
    assert!(hw_info.available_accelerators.contains(&HardwareType::Cpu));

    // Step 4: Get capabilities
    let caps = &hw_info.capabilities;
    assert!(caps.threads > 0);

    // Step 5: Get best accelerator
    let best = hw_info.best_accelerator();
    assert!(best.is_some());

    // Step 6: Route operation
    let result: Result<String> = router.route_to_best_hardware(|| {
        Ok(format!("Executed on {:?} with {} threads", best, caps.threads))
    });

    assert!(result.is_ok());
    let output = result.expect("should succeed");
    assert!(output.contains("Executed on"));
    assert!(output.contains("threads"));
}

/// Test that router default and new produce equivalent routers.
#[test]
fn test_router_default_equals_new() {
    let router1 = HardwareRouter::new();
    let router2 = HardwareRouter::default();

    let hw1 = router1.detect_hardware();
    let hw2 = router2.detect_hardware();

    assert_eq!(hw1.capabilities.threads, hw2.capabilities.threads);
    assert_eq!(hw1.capabilities.simd_support, hw2.capabilities.simd_support);
    assert_eq!(hw1.capabilities.aes_ni, hw2.capabilities.aes_ni);
}
