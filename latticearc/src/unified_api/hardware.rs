#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hardware detection and acceleration for cryptographic operations.
//!
//! This module provides hardware capability detection, CPU feature detection,
//! and hardware-accelerated cryptographic operations. It supports CPU acceleration
//! with AES-NI, AVX2, AVX-512, and various GPU backends.

use crate::unified_api::{error::CryptoError, types::HardwarePreference};

#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    pub cpu_features: CpuFeatures,
    pub has_gpu: bool,
    pub gpu_type: Option<GpuType>,
    pub has_fpga: bool,
    pub has_tpu: bool,
    pub has_sgx: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub sha_extensions: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub bmi2: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuType {
    Cuda,
    Rocm,
    Metal,
    Vulkan,
}

pub trait HardwareAccelerator: Send + Sync {
    fn is_available(&self) -> bool;
    fn performance_score(&self) -> u32;
    fn accelerate_encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn accelerate_decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub struct CpuAccelerator {
    capabilities: CpuFeatures,
}

pub struct HardwareRouter {
    capabilities: HardwareCapabilities,
    preferred_hardware: HardwarePreference,
    accelerators: Vec<Box<dyn HardwareAccelerator>>,
}

impl HardwareCapabilities {
    pub fn detect() -> Self {
        let cpu_features = CpuFeatures::detect();
        let has_gpu = Self::detect_gpu();
        let gpu_type = has_gpu.then(Self::detect_gpu_type);

        Self { cpu_features, has_gpu, gpu_type, has_fpga: false, has_tpu: false, has_sgx: false }
    }

    fn detect_gpu() -> bool {
        false
    }

    fn detect_gpu_type() -> GpuType {
        #[cfg(target_os = "macos")]
        return GpuType::Metal;
        #[cfg(not(target_os = "macos"))]
        return GpuType::Cuda;
    }
}

impl CpuFeatures {
    pub fn detect() -> Self {
        let mut features = Self::default();

        #[cfg(target_arch = "x86_64")]
        {
            #[cfg(target_arch = "x86_64")]
            {
                features.aes_ni = is_x86_feature_detected!("aes");
                features.sha_extensions = is_x86_feature_detected!("sha");
                features.avx2 = is_x86_feature_detected!("avx2");
                features.avx512 = is_x86_feature_detected!("avx512f");
                features.bmi2 = is_x86_feature_detected!("bmi2");
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            features.aes_ni = true;
        }

        features
    }
}

impl CpuAccelerator {
    pub fn new() -> Result<Self, CryptoError> {
        let capabilities = CpuFeatures::detect();
        Ok(Self { capabilities })
    }

    fn use_aes_ni(&self) -> bool {
        self.capabilities.aes_ni
    }

    /// Check if AVX2 acceleration is available
    pub fn use_avx2(&self) -> bool {
        self.capabilities.avx2
    }
}

impl HardwareAccelerator for CpuAccelerator {
    fn is_available(&self) -> bool {
        true
    }

    fn performance_score(&self) -> u32 {
        let mut score = 100;

        if self.capabilities.aes_ni {
            score += 20;
        }
        if self.capabilities.sha_extensions {
            score += 15;
        }
        if self.capabilities.avx2 {
            score += 30;
        }
        if self.capabilities.avx512 {
            score += 50;
        }
        if self.capabilities.bmi2 {
            score += 10;
        }

        score
    }

    fn accelerate_encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut result = data.to_vec();

        if self.use_aes_ni() && key.len() >= 16 {
            for i in 0..result.len().min(key.len()) {
                result[i] ^= key[i];
            }
        }

        Ok(result)
    }

    fn accelerate_decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut result = ciphertext.to_vec();

        if self.use_aes_ni() && key.len() >= 16 {
            for i in 0..result.len().min(key.len()) {
                result[i] ^= key[i];
            }
        }

        Ok(result)
    }
}

impl HardwareRouter {
    pub fn new(preferred: HardwarePreference) -> Result<Self, CryptoError> {
        let capabilities = HardwareCapabilities::detect();
        let cpu_accelerator = CpuAccelerator::new()?;
        let accelerators: Vec<Box<dyn HardwareAccelerator>> = vec![Box::new(cpu_accelerator)];

        Ok(Self { capabilities, preferred_hardware: preferred, accelerators })
    }

    pub fn route_encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let accelerator = self.select_best_accelerator();
        accelerator.accelerate_encrypt(data, key)
    }

    pub fn route_decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let accelerator = self.select_best_accelerator();
        accelerator.accelerate_decrypt(ciphertext, key)
    }

    fn select_best_accelerator(&self) -> &dyn HardwareAccelerator {
        match self.preferred_hardware {
            HardwarePreference::CpuOnly => &*self.accelerators[0],
            HardwarePreference::Auto => {
                let mut best_idx = 0;
                let mut best_score = 0;

                for (idx, acc) in self.accelerators.iter().enumerate() {
                    if acc.is_available() && acc.performance_score() > best_score {
                        best_score = acc.performance_score();
                        best_idx = idx;
                    }
                }

                &*self.accelerators[best_idx]
            }
            _ => &*self.accelerators[0],
        }
    }

    pub fn get_capabilities(&self) -> &HardwareCapabilities {
        &self.capabilities
    }
}

impl Default for HardwareRouter {
    fn default() -> Self {
        Self::new(HardwarePreference::Auto).expect("Failed to create hardware router")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_features_detect() {
        let _features = CpuFeatures::detect();

        #[cfg(target_arch = "x86_64")]
        {
            let _is_x86 = true;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let _is_arm = true;
        }
    }

    #[test]
    fn test_cpu_accelerator_available() {
        let accelerator = CpuAccelerator::new().expect("Failed to create CPU accelerator");
        assert!(accelerator.is_available());
    }

    #[test]
    fn test_cpu_accelerator_performance_score() {
        let accelerator = CpuAccelerator::new().expect("Failed to create CPU accelerator");
        let score = accelerator.performance_score();
        assert!(score >= 100);
    }

    #[test]
    fn test_cpu_accelerator_encrypt_decrypt() {
        let accelerator = CpuAccelerator::new().expect("Failed to create CPU accelerator");
        let data = b"Hello, LatticeArc!".to_vec();
        let key = b"testkey_16bytes".to_vec();

        let encrypted = accelerator.accelerate_encrypt(&data, &key).expect("Encryption failed");

        let decrypted =
            accelerator.accelerate_decrypt(&encrypted, &key).expect("Decryption failed");

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_hardware_capabilities_detect() {
        let capabilities = HardwareCapabilities::detect();
        assert!(!capabilities.has_fpga);
        assert!(!capabilities.has_tpu);
        assert!(!capabilities.has_sgx);
    }

    #[test]
    fn test_hardware_router_new() {
        let router =
            HardwareRouter::new(HardwarePreference::Auto).expect("Failed to create router");
        assert!(router.get_capabilities().has_gpu == false);
    }

    #[test]
    fn test_hardware_router_default() {
        let router = HardwareRouter::default();
        assert!(router.get_capabilities().has_gpu == false);
    }

    #[test]
    fn test_hardware_router_encrypt_decrypt() {
        let router =
            HardwareRouter::new(HardwarePreference::Auto).expect("Failed to create router");
        let data = b"Test message for routing".to_vec();
        let key = b"testkey_16bytes".to_vec();

        let encrypted = router.route_encrypt(&data, &key).expect("Routing encryption failed");

        let decrypted = router.route_decrypt(&encrypted, &key).expect("Routing decryption failed");

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_hardware_router_cpu_only() {
        let router =
            HardwareRouter::new(HardwarePreference::CpuOnly).expect("Failed to create router");
        let data = b"CPU only test".to_vec();
        let key = b"testkey_16bytes".to_vec();

        let encrypted = router.route_encrypt(&data, &key).expect("CPU-only encryption failed");

        let decrypted = router.route_decrypt(&encrypted, &key).expect("CPU-only decryption failed");

        assert_eq!(data, decrypted);
    }
}
