//! Tests for hardware type definitions in arc-core.
//!
//! The stub implementations (HardwareRouter, CpuAccelerator, etc.) have been
//! removed. Real hardware detection and adaptive routing are in the enterprise
//! `arc-enterprise-perf` crate. These tests verify the type system is usable.

#![allow(clippy::redundant_clone)]

use latticearc::types::traits::{HardwareCapabilities, HardwareInfo, HardwareType};

// =============================================================================
// Hardware Type Tests
// =============================================================================

#[test]
fn test_hardware_type_variants_succeeds() {
    let types = [
        HardwareType::Cpu,
        HardwareType::Gpu,
        HardwareType::Fpga,
        HardwareType::Tpu,
        HardwareType::Sgx,
    ];
    assert_eq!(types.len(), 5);
}

#[test]
fn test_hardware_type_equality_succeeds() {
    assert_eq!(HardwareType::Cpu, HardwareType::Cpu);
    assert_ne!(HardwareType::Cpu, HardwareType::Gpu);
}

#[test]
fn test_hardware_type_debug_succeeds() {
    let cpu = HardwareType::Cpu;
    let debug_str = format!("{cpu:?}");
    assert!(debug_str.contains("Cpu"));
}

#[test]
fn test_hardware_type_clone_succeeds() {
    let original = HardwareType::Gpu;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// =============================================================================
// HardwareCapabilities Tests
// =============================================================================

#[test]
fn test_hardware_capabilities_construction_succeeds() {
    let caps = HardwareCapabilities {
        simd_support: true,
        aes_ni: true,
        threads: 8,
        memory: 16_000_000_000,
    };
    assert!(caps.simd_support);
    assert!(caps.aes_ni);
    assert_eq!(caps.threads, 8);
    assert_eq!(caps.memory, 16_000_000_000);
}

#[test]
fn test_hardware_capabilities_minimal_fields_are_correct() {
    let caps = HardwareCapabilities { simd_support: false, aes_ni: false, threads: 1, memory: 0 };
    assert!(!caps.simd_support);
    assert!(!caps.aes_ni);
}

#[test]
fn test_hardware_capabilities_clone_succeeds() {
    let original =
        HardwareCapabilities { simd_support: true, aes_ni: true, threads: 4, memory: 1024 };
    let cloned = original.clone();
    assert_eq!(cloned.threads, 4);
    assert!(cloned.aes_ni);
}

// =============================================================================
// HardwareInfo Tests
// =============================================================================

#[test]
fn test_hardware_info_best_accelerator_prefers_configured_succeeds() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Gpu],
        preferred_accelerator: Some(HardwareType::Gpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 4,
            memory: 0,
        },
    };
    assert_eq!(info.best_accelerator(), Some(&HardwareType::Gpu));
}

#[test]
fn test_hardware_info_best_accelerator_falls_back_to_first_succeeds() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: None,
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 1,
            memory: 0,
        },
    };
    assert_eq!(info.best_accelerator(), Some(&HardwareType::Cpu));
}

#[test]
fn test_hardware_info_best_accelerator_empty_returns_none() {
    let info = HardwareInfo {
        available_accelerators: vec![],
        preferred_accelerator: None,
        capabilities: HardwareCapabilities {
            simd_support: false,
            aes_ni: false,
            threads: 1,
            memory: 0,
        },
    };
    assert_eq!(info.best_accelerator(), None);
}

#[test]
fn test_hardware_info_summary_succeeds() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 8,
            memory: 0,
        },
    };
    let summary = info.summary();
    assert!(summary.contains("Cpu"));
}

#[test]
fn test_hardware_info_clone_succeeds() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Sgx],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 4,
            memory: 0,
        },
    };
    let cloned = info.clone();
    assert_eq!(cloned.available_accelerators.len(), 2);
}
