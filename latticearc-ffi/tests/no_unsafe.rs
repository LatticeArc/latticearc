//! The hand-written source of `latticearc-ffi` must contain no `unsafe`.
//!
//! The workspace forbids `unsafe_code`, which the compiler enforces for the
//! crate's own tokens, but the C ABI that UniFFI's proc macros expand into
//! this crate is exempt from that lint (external macro). This test keeps
//! the human-written half honest by scanning the source files directly.
#![expect(
    clippy::panic,
    reason = "Test helpers abort with a path when a source file cannot be read"
)]

use std::path::Path;

fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.unwrap_or_else(|e| panic!("entry in {}: {e}", dir.display())).path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn hand_written_source_has_no_unsafe() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    assert!(!files.is_empty(), "no sources found under {}", src.display());
    for file in files {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            assert!(
                !code.contains("unsafe"),
                "{}:{}: hand-written FFI source must not use `unsafe`",
                file.display(),
                n.saturating_add(1)
            );
        }
    }
}
