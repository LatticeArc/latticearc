//! Build script for FIPS 140-3 integrity verification
//!
//! This script generates a known-good HMAC-SHA256 digest of the compiled
//! arc-primitives library for runtime integrity verification per FIPS 140-3
//! Section 9.2.2 (Software/Firmware Load Test).

#![allow(missing_docs)] // Build scripts don't need public API docs

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let integrity_file = out_dir.join("integrity_hmac.rs");

    // Check if a production HMAC file exists (generated externally)
    let production_hmac_path = PathBuf::from("PRODUCTION_HMAC.txt");

    let hmac_code = if production_hmac_path.exists() {
        // Production mode: Read pre-computed HMAC
        match load_production_hmac(&production_hmac_path) {
            Some(code) => code,
            None => generate_development_mode(),
        }
    } else {
        // Development mode: No pre-computed HMAC
        generate_development_mode()
    };

    fs::write(&integrity_file, hmac_code).expect("Failed to write integrity_hmac.rs");

    println!("cargo:rerun-if-changed={}", production_hmac_path.display());
}

fn load_production_hmac(path: &PathBuf) -> Option<String> {
    let hmac_hex = match fs::read_to_string(path) {
        Ok(content) => content.trim().to_string(),
        Err(e) => {
            eprintln!("cargo:warning=Failed to read PRODUCTION_HMAC.txt: {}", e);
            return None;
        }
    };

    // Validate hex string length (SHA-256 = 32 bytes = 64 hex chars)
    if hmac_hex.len() != 64 {
        eprintln!(
            "cargo:warning=PRODUCTION_HMAC.txt has wrong length (expected 64 hex chars, got {})",
            hmac_hex.len()
        );
        return None;
    }

    // Parse hex string into bytes
    let mut hmac_bytes = Vec::new();
    for i in (0..hmac_hex.len()).step_by(2) {
        match u8::from_str_radix(&hmac_hex[i..i + 2], 16) {
            Ok(byte) => hmac_bytes.push(byte),
            Err(_) => {
                eprintln!("cargo:warning=Invalid hex in PRODUCTION_HMAC.txt at position {}", i);
                return None;
            }
        }
    }

    Some(format!("pub const EXPECTED_HMAC: Option<&[u8]> = Some(&{:?});", hmac_bytes))
}

fn generate_development_mode() -> String {
    "pub const EXPECTED_HMAC: Option<&[u8]> = None;".to_string()
}
