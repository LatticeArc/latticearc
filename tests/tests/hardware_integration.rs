//! Integration tests for hardware type definitions.
//!
//! Validates that hardware types from arc-core traits module are usable
//! for type-driven design. Real hardware detection is in enterprise.

use latticearc::types::traits::{HardwareCapabilities, HardwareInfo, HardwareType};

// Note: The `HardwareAccelerator` and `HardwareAware` traits were removed in
// the P4.1 dead-code cleanup — they had no production implementors and existed
// only to enable tests like this one. Hardware capability descriptors
// (`HardwareType`, `HardwareInfo`, `HardwareCapabilities`) remain because they
// are used by `types::config::ProductionConfig::preferred_accelerators`.

// =============================================================================
// HardwareInfo Integration
// =============================================================================

#[test]
fn test_hardware_info_with_multiple_accelerators_succeeds() {
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
fn test_hardware_info_summary_format_has_correct_size() {
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
fn test_hardware_types_are_send_succeeds() {
    fn assert_send<T: Send>() {}
    assert_send::<HardwareType>();
    assert_send::<HardwareCapabilities>();
    assert_send::<HardwareInfo>();
}
