//! Build script for arc-prelude crate.
//!
//! This build script configures custom cfg flags for the crate.

/// Main entry point for the build script.
///
/// Configures the `kani` cfg flag for formal verification support.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
