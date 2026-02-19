//! Integration tests for hardware type definitions.
//!
//! Validates that hardware types from arc-core traits module are usable
//! for type-driven design. Real hardware detection is in enterprise.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(dead_code)]

use latticearc::unified_api::traits::{
    HardwareAccelerator, HardwareCapabilities, HardwareInfo, HardwareType,
};

// =============================================================================
// Custom Accelerator Implementation (demonstrates trait is implementable)
// =============================================================================

struct TestAccelerator {
    hw_type: HardwareType,
    available: bool,
}

impl HardwareAccelerator for TestAccelerator {
    fn name(&self) -> &str {
        "Test Accelerator"
    }

    fn hardware_type(&self) -> HardwareType {
        self.hw_type.clone()
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

#[test]
fn test_custom_accelerator_implementation() {
    let accel = TestAccelerator { hw_type: HardwareType::Cpu, available: true };
    assert_eq!(accel.name(), "Test Accelerator");
    assert_eq!(accel.hardware_type(), HardwareType::Cpu);
    assert!(accel.is_available());
}

#[test]
fn test_unavailable_accelerator() {
    let accel = TestAccelerator { hw_type: HardwareType::Gpu, available: false };
    assert!(!accel.is_available());
}

// =============================================================================
// HardwareInfo Integration
// =============================================================================

#[test]
fn test_hardware_info_with_multiple_accelerators() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Gpu, HardwareType::Sgx],
        preferred_accelerator: Some(HardwareType::Sgx),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 16,
            memory: 32_000_000_000,
        },
    };

    // Preferred should take priority
    assert_eq!(info.best_accelerator(), Some(&HardwareType::Sgx));
    assert_eq!(info.available_accelerators.len(), 3);
    assert_eq!(info.capabilities.threads, 16);
}

#[test]
fn test_hardware_info_summary_format() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu, HardwareType::Fpga],
        preferred_accelerator: Some(HardwareType::Fpga),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: false,
            threads: 2,
            memory: 4096,
        },
    };
    let summary = info.summary();
    assert!(summary.contains("Fpga"));
    assert!(summary.contains("Available"));
}

// =============================================================================
// Thread Safety (types are Send + Sync via standard derives)
// =============================================================================

#[test]
fn test_hardware_types_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<HardwareType>();
    assert_send::<HardwareCapabilities>();
    assert_send::<HardwareInfo>();
}
