//! Hardware detection type definitions.
//!
//! This module re-exports hardware-related types from [`crate::traits`].
//!
//! **Note:** The stub implementations (`HardwareRouter`, `CpuAccelerator`,
//! `GpuAccelerator`, `FpgaAccelerator`, `SgxAccelerator`, `TpmAccelerator`)
//! have been removed. They were dead code — `HardwareRouter` always returned
//! `[Cpu]` and `route_to_best_hardware()` ignored the selected accelerator.
//!
//! Real hardware detection and adaptive algorithm routing is provided by the
//! enterprise `arc-enterprise-perf` crate, which detects CPU features, GPU,
//! HSM/TPM, and feeds the `AdaptiveSelector`.
//!
//! The underlying crypto library (`aws-lc-rs`) already handles AES-NI, SHA,
//! and SIMD acceleration internally at the C level.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

pub use crate::unified_api::traits::{
    HardwareAccelerator, HardwareAware, HardwareCapabilities, HardwareInfo, HardwareType,
};
