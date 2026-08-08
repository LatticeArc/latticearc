//! Shared test fixtures for `latticearc/tests/*.rs` integration tests.
//!
//! This is a directory module (`support/mod.rs`), included via `mod support;`
//! from individual test files — cargo's test auto-discovery only treats
//! `.rs` files directly under `tests/` as separate test binaries, so this
//! module does not become its own `cargo test` target. It is instead
//! recompiled as part of each consuming test binary's crate.
//!
//! Keep this module to fixtures that are genuinely duplicated across
//! multiple test files; do not add speculative helpers.

// Each consuming test binary recompiles this module and uses its own subset
// of the fixtures — an unused-here helper is used elsewhere, so the workspace
// deny(dead_code) wall must not apply inside this support module.
#![allow(dead_code)]

use latticearc::primitives::ec::ed25519::Ed25519KeyPair;
// `generate()` comes from the sealed `EcKeyPair` trait.
use latticearc::primitives::ec::traits::EcKeyPair;

/// Generate a fresh Ed25519 keypair.
///
/// Replaces the repeated `Ed25519KeyPair::generate().unwrap()` /
/// `.expect(...)` pattern used by tests that only need *some* valid
/// keypair, not a specific one.
///
/// # Panics
/// Panics if keypair generation fails. Acceptable in test fixtures: the
/// consuming test files already carry `#![allow(clippy::expect_used)]`.
pub fn ed25519_keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::generate().expect("ed25519 keypair generation must succeed in tests")
}
