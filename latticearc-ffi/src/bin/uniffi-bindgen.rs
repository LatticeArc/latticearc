//! Thin wrapper around UniFFI's binding generator so that
//! `cargo run -p latticearc-ffi --features bindgen --bin uniffi-bindgen`
//! produces Swift and Kotlin sources that match the pinned `uniffi` version
//! compiled into the library.

fn main() {
    uniffi::uniffi_bindgen_main();
}
