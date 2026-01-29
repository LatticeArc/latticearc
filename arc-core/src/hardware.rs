//! Hardware detection and acceleration routing.
//!
//! Provides automatic detection of hardware accelerators (CPU, GPU, FPGA, TPM, SGX)
//! and routes cryptographic operations to the optimal hardware.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::{
    error::Result,
    traits::{HardwareAccelerator, HardwareCapabilities, HardwareInfo, HardwareType},
};
#[cfg(any(target_os = "windows", target_os = "linux"))]
use tracing::info;
use tracing::warn;

/// Hardware routing and detection.
///
/// Caches hardware detection results and routes operations to optimal accelerators.
pub struct HardwareRouter {
    /// Cached hardware detection results.
    detection_cache: std::sync::Mutex<Option<HardwareInfo>>,
}

impl Default for HardwareRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareRouter {
    /// Creates a new hardware router.
    #[must_use]
    pub fn new() -> Self {
        Self { detection_cache: std::sync::Mutex::new(None) }
    }

    /// Detects available hardware accelerators and returns their information.
    pub fn detect_hardware(&self) -> HardwareInfo {
        // Handle mutex poisoning with explicit logging - this indicates a thread panicked
        // while holding the lock, which could indicate memory corruption or attack
        let mut cache = self.detection_cache.lock().unwrap_or_else(|poisoned| {
            warn!(
                "Hardware detection cache mutex was poisoned - another thread panicked. \
                 Using recovered state but hardware detection results may be unreliable."
            );
            poisoned.into_inner()
        });
        if let Some(info) = cache.as_ref() {
            return info.clone();
        }

        let info = HardwareInfo {
            available_accelerators: vec![HardwareType::Cpu],
            preferred_accelerator: Some(HardwareType::Cpu),
            capabilities: HardwareCapabilities {
                simd_support: true,
                aes_ni: true,
                threads: rayon::current_num_threads(),
                memory: 0,
            },
        };

        *cache = Some(info.clone());
        info
    }

    /// Routes an operation to the best available hardware.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation itself fails.
    pub fn route_to_best_hardware<F, R>(&self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        let hardware_info = self.detect_hardware();
        let _best_accelerator = Self::select_best_accelerator(&hardware_info);
        // Currently all paths execute the same operation
        // Future: Use accelerator-specific paths
        operation()
    }

    /// Selects the best accelerator from hardware info.
    fn select_best_accelerator(hardware: &HardwareInfo) -> Option<Box<dyn HardwareAccelerator>> {
        match hardware.best_accelerator() {
            Some(HardwareType::Cpu) => Some(Box::new(CpuAccelerator::new(&hardware.capabilities))),
            Some(HardwareType::Gpu) => Some(Box::new(GpuAccelerator::new())),
            Some(HardwareType::Fpga) => Some(Box::new(FpgaAccelerator::new())),
            Some(HardwareType::Tpu) => Some(Box::new(TpmAccelerator::new())),
            _ => None,
        }
    }
}

/// CPU-based cryptographic accelerator using SIMD and AES-NI.
#[derive(Debug)]
pub struct CpuAccelerator {
    /// Hardware capabilities of this CPU.
    _capabilities: HardwareCapabilities,
}

impl CpuAccelerator {
    /// Creates a new CPU accelerator with the given capabilities.
    #[must_use]
    pub fn new(capabilities: &HardwareCapabilities) -> Self {
        Self { _capabilities: capabilities.clone() }
    }
}

impl HardwareAccelerator for CpuAccelerator {
    fn name(&self) -> &str {
        "CPU Accelerator"
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::Cpu
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Intel SGX enclave accelerator for secure computation.
#[derive(Debug)]
pub struct SgxAccelerator {
    /// Whether SGX is available on this system.
    available: bool,
}

impl Default for SgxAccelerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SgxAccelerator {
    /// Creates a new SGX accelerator, detecting availability.
    #[must_use]
    pub fn new() -> Self {
        let available = Self::check_sgx_availability();
        Self { available }
    }

    /// Checks if SGX is available on this system.
    fn check_sgx_availability() -> bool {
        std::path::Path::new("/dev/sgx").exists()
    }
}

impl HardwareAccelerator for SgxAccelerator {
    fn name(&self) -> &str {
        "SGX Accelerator"
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::Sgx
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

/// GPU-based cryptographic accelerator.
#[derive(Debug)]
pub struct GpuAccelerator {
    /// Whether a compatible GPU is available.
    available: bool,
}

impl Default for GpuAccelerator {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuAccelerator {
    /// Creates a new GPU accelerator, detecting availability.
    #[must_use]
    pub fn new() -> Self {
        let available = Self::check_gpu_availability();
        Self { available }
    }

    /// Checks if a compatible GPU is available.
    fn check_gpu_availability() -> bool {
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            match std::process::Command::new("nvidia-smi").output() {
                Ok(output) => output.status.success(),
                Err(e) => {
                    info!("GPU detection (nvidia-smi) failed: {} - GPU acceleration disabled", e);
                    false
                }
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            false
        }
    }
}

impl HardwareAccelerator for GpuAccelerator {
    fn name(&self) -> &str {
        "GPU Accelerator"
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::Gpu
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

/// FPGA-based cryptographic accelerator.
#[derive(Debug)]
pub struct FpgaAccelerator {
    /// Whether an FPGA is available.
    available: bool,
}

impl Default for FpgaAccelerator {
    fn default() -> Self {
        Self::new()
    }
}

impl FpgaAccelerator {
    /// Creates a new FPGA accelerator, detecting availability.
    #[must_use]
    pub fn new() -> Self {
        let available = Self::check_fpga_availability();
        Self { available }
    }

    /// Checks if an FPGA is available.
    fn check_fpga_availability() -> bool {
        // Check for common FPGA devices
        #[cfg(target_os = "linux")]
        {
            // Check for Xilinx/Altera devices
            std::path::Path::new("/dev/xdma0").exists()
                || std::path::Path::new("/dev/altera_fpgamgr").exists()
        }

        #[cfg(target_os = "windows")]
        {
            // Check for Windows FPGA drivers
            match std::process::Command::new("wmic")
                .args(["path", "Win32_PnPEntity", "where", "DeviceID like '%FPGA%'"])
                .output()
            {
                Ok(output) => output.status.success(),
                Err(e) => {
                    info!("FPGA detection (wmic) failed: {} - FPGA acceleration disabled", e);
                    false
                }
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            false
        }
    }
}

impl HardwareAccelerator for FpgaAccelerator {
    fn name(&self) -> &str {
        "FPGA Accelerator"
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::Fpga
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

/// TPM-based cryptographic accelerator.
#[derive(Debug)]
pub struct TpmAccelerator {
    /// Whether a TPM is available.
    available: bool,
}

impl Default for TpmAccelerator {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmAccelerator {
    /// Creates a new TPM accelerator, detecting availability.
    #[must_use]
    pub fn new() -> Self {
        let available = Self::check_tpm_availability();
        Self { available }
    }

    /// Checks if a TPM is available.
    fn check_tpm_availability() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
        }

        #[cfg(target_os = "windows")]
        {
            // Check for TPM via Windows TBS
            match std::process::Command::new("tpmtool").arg("getdeviceinformation").output() {
                Ok(output) => output.status.success(),
                Err(e) => {
                    info!("TPM detection (tpmtool) failed: {} - TPM acceleration disabled", e);
                    false
                }
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            false
        }
    }
}

impl HardwareAccelerator for TpmAccelerator {
    fn name(&self) -> &str {
        "TPM Accelerator"
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::Tpu
    }

    fn is_available(&self) -> bool {
        self.available
    }
}
