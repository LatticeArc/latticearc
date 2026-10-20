//! Swift-specific generator (headers, module map and sources as separate
//! steps) used by `scripts/ffi/build-xcframework.sh`.

fn main() {
    uniffi::uniffi_bindgen_swift();
}
