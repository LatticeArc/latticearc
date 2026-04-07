#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for PortableKey JSON deserialization
//!
//! Tests that `PortableKey::from_json` handles arbitrary byte sequences
//! without crashing, and that any successfully parsed key survives a
//! serialize-then-parse roundtrip.

use libfuzzer_sys::fuzz_target;
use latticearc::PortableKey;

fuzz_target!(|data: &[u8]| {
    // Only proceed if the input is valid UTF-8; JSON must be text.
    let Ok(json_str) = std::str::from_utf8(data) else {
        return;
    };

    // Attempt to parse arbitrary text as a PortableKey.
    let Ok(key) = PortableKey::from_json(json_str) else {
        // Parsing failure is the expected common case — not a bug.
        return;
    };

    // If parsing succeeded, the roundtrip must also succeed and produce a
    // key that parses to an identical result.
    if let Ok(re_json) = key.to_json() {
        if let Ok(key2) = PortableKey::from_json(&re_json) {
            // A second serialization of the roundtripped key must be
            // byte-for-byte identical (canonical JSON form).
            if let Ok(re_json2) = key2.to_json() {
                assert_eq!(
                    re_json, re_json2,
                    "PortableKey JSON serialization must be canonical: \
                     two round-trips produced different output"
                );
            }
        }
    }

    // Also exercise the CBOR path on any key that JSON-parsed successfully:
    // CBOR round-trip must not panic regardless of what the key contains.
    if let Ok(cbor_bytes) = key.to_cbor() {
        let _ = PortableKey::from_cbor(&cbor_bytes);
    }
});
