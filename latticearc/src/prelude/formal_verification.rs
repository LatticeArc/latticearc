//! Documentation-only stub for formal-verification call-out.
//!
//! The previously-exported `run_formal_verification()` was a no-op that
//! only emitted three `tracing::info!` lines telling the operator how
//! to install Kani — it performed no verification, yet its name in the
//! prelude implied otherwise. The function was therefore decorative /
//! misleading assurance and has been removed; this docstring is the
//! replacement.
//!
//! Real Kani proofs live in the crate under `#[cfg(kani)]` and run via
//! `cargo kani --package latticearc`. Install Kani with
//! `cargo install --locked kani-verifier` (Linux x86_64 / macOS
//! aarch64 only). The CI `cargo kani --only-codegen` step exercises
//! the proof harnesses' build path on every push; full proofs run on
//! the dedicated `kani-proofs.yml` workflow.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
