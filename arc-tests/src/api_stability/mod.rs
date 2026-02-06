//! API Stability Tests
//!
//! This module ensures backward compatibility across LatticeArc versions.
//!
//! ## Test Categories
//!
//! - **Serialization**: Key and ciphertext format stability
//! - **Key Formats**: Public/private key byte representations
//! - **Error Types**: Error variant stability
//!
//! ## Purpose
//!
//! Enterprise users need stable APIs across versions. These tests catch
//! accidental breaking changes before release.

pub mod key_formats;
pub mod serialization;

#[cfg(test)]
mod tests {
    #[test]
    fn api_stability_modules_load() {
        // Ensures all API stability test modules compile correctly
    }
}
