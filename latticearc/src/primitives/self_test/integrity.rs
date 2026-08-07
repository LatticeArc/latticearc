#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::{LatticeArcError, Result};
use std::sync::atomic::Ordering;

use super::INTEGRITY_TEST_CONFIGURED;

// =============================================================================
// Integrity Test
// =============================================================================

/// Heuristic: does the file at `path` look like a LatticeArc artifact?
///
/// `current_exe()` returns the path to the running executable; when
/// LatticeArc is loaded as a dynamic library by a host (Python, Node,
/// JVM, etc.) that path is the host interpreter, not the library. This
/// helper recognises three kinds of legitimate LatticeArc-on-disk
/// artifacts:
///   * the platform-specific shared library (`liblatticearc.so` /
///     `liblatticearc.dylib` / `latticearc.dll`)
///   * the LatticeArc CLI binary (`latticearc-cli` / `latticearc-cli.exe`)
///   * any cargo-generated `<crate-name>-<16-hex>` binary under a
///     `target` directory. The crate-name prefix is intentionally
///     unconstrained: integration tests across the workspace produce
///     binaries named after the test file, not after `latticearc`, and
///     they all statically link this crate.
///
/// Anything else is treated as an unverifiable host process and the
/// integrity test refuses to HMAC it.
fn path_looks_like_latticearc_module(path: &std::path::Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    // tightened from a permissive
    // `starts_with("latticearc")` plus a blanket `target/deps/` accept
    // to (a) an exact list of names produced by this build, plus
    // (b) cargo-test binary recognition via the `<crate-name>-<16-hex>`
    // suffix shape inside `target/{debug,release}/deps/`. Previously
    // a binary named `latticearc-evil-host` would have been HMAC-
    // checked against the EXPECTED_HMAC, surfacing as "module
    // integrity OK" for a non-LatticeArc image.
    //
    // Note: the cargo-deps shape check intentionally does NOT require
    // a `latticearc` crate-name prefix — integration tests under
    // `latticearc/tests/`, `tests/tests/`, and other workspace
    // members produce binaries whose crate name reflects the test
    // file (e.g. `primitives_self_test_conditional_kats-<hex>`),
    // none of which start with `latticearc`. They all statically
    // link the latticearc crate and are legitimate consumers, so
    // the integrity test must accept them. The 16-hex-suffix shape
    // is what excludes adversary binaries: a hand-crafted binary
    // dropped into `deps/` to fake the integrity check would either
    // (i) lack the 16-hex suffix (cargo always generates one) or
    // (ii) be a real cargo-test binary, in which case the question
    // reduces to "does the developer trust their own `target/`",
    // which the workspace already assumes.
    let exact_names = [
        "liblatticearc.so",
        "liblatticearc.dylib",
        "latticearc.dll",
        // Downstream binary name. The package is `latticearc-cli` but its
        // `[[bin]] name = "latticearc"`, so `current_exe()` reports the
        // short form — both spellings must be accepted to keep FIPS POST
        // (which calls `path_looks_like_latticearc_module`) from rejecting
        // legitimate cli invocations and SIGABRT-ing during keygen.
        "latticearc",
        "latticearc.exe",
        "latticearc-cli",
        "latticearc-cli.exe",
    ];
    if exact_names.iter().any(|n| lower == *n) {
        return true;
    }
    // Accept any cargo-generated test binary that sits under a `target`
    // ancestor. Deliberately does NOT pin the directory that immediately
    // contains the binary.
    //
    // Cargo documents the build-dir layout as "internal to Cargo, and
    // subject to change", and it does change: build-dir layout v2
    // (rust-lang/cargo#17258, default on nightly from 2026-07-24, and
    // stabilized for 1.99.0 by rust-lang/cargo#16807) moved unit-test
    // binaries out of
    //     target/<triple>/<profile>/deps/<crate>-<hash>
    // and into
    //     target/<triple>/<profile>/build/<pkg>/<hash>/out/<crate>-<hash>
    // A check that required the parent to be `deps` rejected every test
    // binary the moment that landed, which failed the integrity test,
    // aborted the FIPS POST, and SIGABRT'd the whole test runner.
    //
    // So the shape we match on is the one cargo does NOT reserve the
    // right to reshuffle: the `<crate-name>-<16-hex>` file name (checked
    // below) plus containment under `target`. Pinning any intermediate
    // directory name re-creates the same outage on the next layout
    // revision.
    //
    // Security note: this is a "did we find our own artifact, or the host
    // interpreter that dlopen'd us" check, NOT the tamper gate — an
    // adversary-injected binary is rejected by HMAC mismatch, not by
    // path. Which subdirectory of `target/` the build system chose is
    // not a security property: an attacker who can write into
    // `target/<anything>/` can write into `target/release/deps/` too.
    //
    // Hop bound: the deepest known layout is a nested tool target dir
    // plus an explicit `--target <triple>` under layout v2 —
    // `target/llvm-cov-target/<triple>/<profile>/build/<pkg>/<hash>/out/`
    // — 8 hops from the binary's parent. Bounded at 12 rather than 8:
    // the bound exists only to stop the walk wandering to the filesystem
    // root, it is not a trust boundary, and sizing it flush against the
    // deepest layout known today is exactly the brittleness that caused
    // the layout-v2 outage. The margin costs nothing.
    const MAX_TARGET_ANCESTOR_HOPS: usize = 12;
    let under_target = path.parent().is_some_and(|p| {
        p.ancestors()
            .take(MAX_TARGET_ANCESTOR_HOPS)
            .any(|a| a.file_name().and_then(|n| n.to_str()) == Some("target"))
    });
    if under_target {
        // Strip `.exe` if present, then split on the LAST `-` to get
        // crate-name vs hex-suffix. Accept any 16-hex-suffix file under
        // `target/` — see the comment above for why neither the
        // crate-name prefix nor the containing directory is constrained.
        let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
        if let Some((_crate_name, suffix)) = stem.rsplit_once('-')
            && suffix.len() == 16
            && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            return true;
        }
    }
    false
}

/// Software/Firmware Integrity Test
///
/// FIPS 140-3 Software/Firmware Load Test (Section 9.2.2).
///
/// Verifies the integrity of the cryptographic module at power-up by
/// computing an HMAC-SHA256 digest of the on-disk module artifact and
/// comparing it against the build-time-recorded expected value.
///
/// # Module location
///
/// The module path is resolved via `std::env::current_exe()` and then
/// cross-checked with [`path_looks_like_latticearc_module`]. If the
/// resolved path does not look like a LatticeArc shared library or
/// LatticeArc-bearing binary (e.g. when the library is loaded by a
/// host interpreter and `current_exe()` returns the interpreter
/// itself), the test returns an explicit "cannot locate" error rather
/// than HMACing the wrong file. Without `unsafe`, which the workspace
/// `unsafe_code` lint forbids, there is no portable way to call the
/// platform dynamic-loader APIs (`dladdr`, `dl_iterate_phdr`,
/// `GetModuleFileName`) that would recover the library's path
/// directly; the dynamic-load case must be handled by the deployment
/// (e.g. by also shipping a static-link CLI that runs the integrity
/// test out-of-band).
///
/// # Errors
///
/// Returns error if:
/// - `current_exe()` is unavailable
/// - The resolved path does not look like a LatticeArc artifact
/// - The artifact cannot be read
/// - HMAC computation fails
/// - The computed HMAC does not match the build-time expected value
pub fn integrity_test() -> Result<()> {
    // FIPS requires using a cryptographic key for HMAC
    // For a self-contained integrity test, we use a deterministic key derived
    // from the module identity. In production FIPS, this would come from HSM/TPM.
    const INTEGRITY_KEY: &[u8] = crate::types::domains::MODULE_INTEGRITY_HMAC_KEY;

    // Locate the latticearc module binary on disk.
    //
    // `std::env::current_exe()` returns the path to the *host* binary,
    // which is correct only when latticearc is statically linked into
    // that binary. When latticearc is loaded as a `.so`/`.dylib`/`.dll`
    // (e.g. from a Python or Node.js extension), `current_exe()` points
    // at the host interpreter, and HMACing it would silently verify
    // the wrong file.
    //
    // Without `unsafe` (forbidden crate-wide) we cannot call
    // platform dynamic-loader APIs (`dladdr`, `dl_iterate_phdr`,
    // `GetModuleFileName`) to recover the library's own path. Instead
    // we read `current_exe()`, then check whether the resolved file
    // name matches one of the LatticeArc artifact names compiled
    // into this build (`liblatticearc.so`, `liblatticearc.dylib`,
    // `latticearc.dll`, or any binary that links them statically).
    // If the path looks like a host-process executable rather than the
    // LatticeArc library, return an explicit "cannot locate" error so
    // FIPS callers see the integrity gap rather than a silent
    // false-positive verification of the wrong file.
    let module_path = std::env::current_exe().map_err(|e| LatticeArcError::ValidationError {
        message: format!("Integrity test: cannot locate module binary: {e}"),
    })?;

    if !path_looks_like_latticearc_module(&module_path) {
        return Err(LatticeArcError::ValidationError {
            message: format!(
                "Integrity test: current_exe() = {:?} does not appear to be a \
                 LatticeArc library or a binary that statically links it. \
                 This build cannot verify dynamic-library integrity without \
                 platform dynamic-loader APIs (forbidden by the workspace \
                 `unsafe_code` lint). Run the integrity test from a binary \
                 that statically links latticearc, or supply an external \
                 library path via the FIPS deployment manifest.",
                module_path,
            ),
        });
    }

    // Read the module binary with an explicit upper bound. The path is
    // `current_exe()` (not adversary-controlled), but a runaway binary
    // size or a /dev/* substitution could still OOM the process. 512 MB
    // is well above any realistic statically-linked LatticeArc binary
    // and well below the smallest deployment target's RAM ceiling.
    const MAX_MODULE_SIZE: u64 = 512 * 1024 * 1024;
    use std::io::Read;
    let f = std::fs::File::open(&module_path).map_err(|e| LatticeArcError::ValidationError {
        message: format!("Integrity test: cannot open module binary: {e}"),
    })?;
    let mut module_bytes = Vec::new();
    f.take(MAX_MODULE_SIZE + 1).read_to_end(&mut module_bytes).map_err(|e| {
        LatticeArcError::ValidationError {
            message: format!("Integrity test: cannot read module binary: {e}"),
        }
    })?;
    if module_bytes.len() as u64 > MAX_MODULE_SIZE {
        return Err(LatticeArcError::ValidationError {
            message: format!("Integrity test: module binary exceeds {MAX_MODULE_SIZE}-byte cap"),
        });
    }

    // Compute HMAC-SHA256 over the module binary via the primitives wrapper
    // (FIPS-validated aws-lc-rs backend).
    let computed_hmac = crate::primitives::mac::hmac::hmac_sha256(INTEGRITY_KEY, &module_bytes)
        .map_err(|e| LatticeArcError::ValidationError {
            message: format!("Integrity test: HMAC computation failed: {e}"),
        })?;

    // In a production FIPS module, the expected HMAC would be:
    // 1. Computed in a secure build environment
    // 2. Stored in tamper-evident storage (HSM, TPM, or signed manifest)
    // 3. Verified against the runtime-computed value
    //
    // For this implementation, we use a reference HMAC that represents the
    // "known-good" state. This demonstrates the verification mechanism.
    //
    // NOTE: The expected HMAC must be updated whenever the module is recompiled.
    // For production FIPS certification, implement automated HMAC generation
    // in the build pipeline.

    // Expected HMAC generated by build script
    // The build script creates a file defining EXPECTED_HMAC in OUT_DIR
    // We include it here to get the constant value
    mod generated {
        include!(concat!(env!("OUT_DIR"), "/integrity_hmac.rs"));
    }
    let expected_hmac = generated::EXPECTED_HMAC;

    // "No HMAC configured" is a deployment-configuration condition, NOT a
    // tamper detection. The integrity test couldn't run — that's different
    // from "the integrity test ran and detected tamper". We always return
    // Ok here (with a loud warning) so `initialize_and_test`'s FIPS 140-3
    // §9.1 abort path fires ONLY on real tamper (HMAC mismatch) or KAT
    // failures, never on a missing config file. Under the
    // `fips-strict-integrity` feature, `verify_operational` separately
    // rejects operational entry when `INTEGRITY_TEST_CONFIGURED` is still
    // false at gate time — that's the right layer to enforce "config
    // must be present", because the caller can handle a Result whereas
    // initialize_and_test can only abort.
    let Some(expected_hmac) = expected_hmac else {
        tracing::warn!(
            hmac_computed = ?computed_hmac.as_slice(),
            "FIPS integrity test SKIPPED — no PRODUCTION_HMAC.txt configured. \
             Module-integrity verification did NOT run. Provision \
             PRODUCTION_HMAC.txt for FIPS 140-3 §9 compliance; under the \
             fips-strict-integrity feature, verify_operational will refuse \
             to enter operational state until this is configured."
        );
        #[expect(
            clippy::print_stderr,
            reason = "Operator-facing diagnostic — must surface even when tracing is unconfigured"
        )]
        {
            eprintln!("WARNING: FIPS Integrity Test SKIPPED (no PRODUCTION_HMAC.txt)");
            eprintln!("   Module-integrity verification did NOT run.");
            eprintln!("   Computed HMAC: {:02x?}", computed_hmac.as_slice());
            eprintln!(
                "   Build with --features fips (or --features fips-strict-integrity) \
                 and provision PRODUCTION_HMAC.txt for FIPS 140-3 §9 compliance."
            );
        }
        // INTEGRITY_TEST_CONFIGURED stays false — strict-integrity gate
        // in `verify_operational` reads this and refuses Ok.
        return Ok(());
    };
    // From here on, an HMAC IS configured and a mismatch indicates real
    // tamper — record the fact so the strict-integrity gate knows a real
    // check ran. Store before the comparison so a panicking compare (which
    // cannot happen with `ct_eq` but is belt-and-suspenders) doesn't leave
    // the flag false on a path where tamper detection actually executed.
    INTEGRITY_TEST_CONFIGURED.store(true, Ordering::SeqCst);

    // Constant-time comparison using subtle crate
    use subtle::ConstantTimeEq;
    let hmac_match = computed_hmac.ct_eq(expected_hmac);

    if hmac_match.into() {
        Ok(())
    } else {
        // Integrity violation detected
        Err(LatticeArcError::ValidationError {
            message: "FIPS Integrity Test FAILED: Module binary has been modified or corrupted. \
                     This is a critical security violation."
                .to_string(),
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_looks_like_latticearc_module_accepts_known_shapes() {
        use std::path::PathBuf;

        // Exact-name binaries (CLI / dynamic library names).
        for name in [
            "liblatticearc.so",
            "liblatticearc.dylib",
            "latticearc.dll",
            "latticearc",
            "latticearc.exe",
            "latticearc-cli",
            "latticearc-cli.exe",
        ] {
            assert!(
                path_looks_like_latticearc_module(&PathBuf::from(name)),
                "exact-name binary should be accepted: {name}"
            );
        }

        // Cargo-generated `<crate>-<16-hex>` binaries under `target`.
        // The containing directory is deliberately not pinned: cargo
        // treats the build-dir layout as internal and has already moved
        // these binaries once (layout v1 `deps/` -> layout v2
        // `build/<pkg>/<hash>/out/`).
        for path in [
            // Layout v1: standard `target/<profile>/deps/`.
            "/work/repo/target/release/deps/latticearc-0123456789abcdef",
            "/work/repo/target/debug/deps/audit_regression_signatures-fedcba9876543210",
            // Layout v1 with an explicit `--target <triple>`.
            "/work/repo/target/x86_64-unknown-linux-gnu/debug/deps/latticearc-53a673efabc83b87",
            // Custom profile (e.g. `[profile.valgrind]`).
            "/work/repo/target/valgrind/deps/latticearc-0123456789abcdef",
            // Directly under the profile dir, with no intervening
            // artifact directory at all. Accepted because the trust
            // scope is `target/` plus the cargo file-name shape, not
            // any particular subdirectory — the same reason layout v2
            // is accepted below.
            "/work/repo/target/release/latticearc-0123456789abcdef",
            // `cargo llvm-cov` nested target dir.
            "/work/repo/target/llvm-cov-target/release/deps/latticearc-0123456789abcdef",
            // Layout v2 (`build/<pkg>/<hash>/out/`), as produced by the
            // sanitizer jobs' `cargo +nightly test -Z build-std
            // --target x86_64-unknown-linux-gnu`. This exact path shape
            // aborted the FIPS POST on every sanitizer run once cargo
            // enabled layout v2 by default on nightly.
            "/work/repo/target/x86_64-unknown-linux-gnu/debug/build/latticearc/\
             2dfe6b1649723639/out/latticearc-2dfe6b1649723639",
            // Layout v2 without an explicit target triple.
            "/work/repo/target/debug/build/latticearc/2dfe6b1649723639/out/\
             latticearc-2dfe6b1649723639",
        ] {
            assert!(
                path_looks_like_latticearc_module(&PathBuf::from(path)),
                "cargo-generated binary under target/ should be accepted: {path}"
            );
        }
    }

    #[test]
    fn test_path_looks_like_latticearc_module_rejects_adversarial_shapes() {
        use std::path::PathBuf;

        for path in [
            // Wrong hex-suffix length (15 vs required 16).
            "/work/repo/target/release/deps/latticearc-0123456789abcde",
            // Suffix is not hex.
            "/work/repo/target/release/deps/latticearc-evil-not-hex-here",
            // Not under any `target` ancestor — host interpreter case.
            // This is the case the helper actually exists to catch: a
            // Python/Node process that dlopen'd liblatticearc.
            "/usr/bin/python3.12",
            "/opt/node/bin/node",
            // Cargo-shaped file name, but no `target` ancestor: an
            // installed artifact is not a build-tree artifact.
            "/usr/lib/python3/dist-packages/latticearc-0123456789abcdef",
            // `target` exists but is further up than the ancestor walk
            // goes, so the walk stops before reaching it rather than
            // climbing to the filesystem root. Deeper than any real
            // cargo/llvm-cov layout — this pins the walk's termination,
            // not a trust boundary.
            "/builds/foo/target/a/b/c/d/e/f/g/h/i/j/k/deps/latticearc-0123456789abcdef",
        ] {
            assert!(
                !path_looks_like_latticearc_module(&PathBuf::from(path)),
                "non-LatticeArc path should be rejected: {path}"
            );
        }
    }

    #[test]
    fn test_integrity_test_returns_ok_when_no_hmac_regardless_of_feature() {
        // Pre-tamper-check semantics: "couldn't run" must not be confused
        // with "ran and detected tamper". integrity_test returns Ok and
        // leaves `INTEGRITY_TEST_CONFIGURED` false; the strict gate is
        // applied separately at the verify_operational layer.
        assert!(
            integrity_test().is_ok(),
            "missing PRODUCTION_HMAC.txt is a deployment-config condition, not tamper — \
             integrity_test must Ok so initialize_and_test does not §9.1-abort on it"
        );
    }
}
