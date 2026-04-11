#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for EncryptedData and EncryptedOutput JSON deserialization
//!
//! Tests that `deserialize_encrypted_data` and `deserialize_encrypted_output`
//! handle arbitrary byte sequences without crashing, and that any
//! successfully deserialised value survives a serialize-then-parse roundtrip.

use latticearc::{
    deserialize_encrypted_data, deserialize_encrypted_output, serialize_encrypted_data,
    serialize_encrypted_output,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // JSON must be valid UTF-8.
    let Ok(json_str) = std::str::from_utf8(data) else {
        return;
    };

    // -----------------------------------------------------------------------
    // EncryptedData (legacy v1 format)
    // -----------------------------------------------------------------------
    if let Ok(encrypted) = deserialize_encrypted_data(json_str) {
        // Roundtrip: serialize back and re-parse.
        if let Ok(re_json) = serialize_encrypted_data(&encrypted) {
            if let Ok(encrypted2) = deserialize_encrypted_data(&re_json) {
                // A second serialization must be identical (canonical).
                if let Ok(re_json2) = serialize_encrypted_data(&encrypted2) {
                    assert_eq!(
                        re_json, re_json2,
                        "EncryptedData JSON serialization must be canonical"
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // EncryptedOutput (v2 format with hybrid support)
    // -----------------------------------------------------------------------
    if let Ok(output) = deserialize_encrypted_output(json_str) {
        // Roundtrip: serialize back and re-parse.
        if let Ok(re_json) = serialize_encrypted_output(&output) {
            if let Ok(output2) = deserialize_encrypted_output(&re_json) {
                // A second serialization must be identical (canonical).
                if let Ok(re_json2) = serialize_encrypted_output(&output2) {
                    assert_eq!(
                        re_json, re_json2,
                        "EncryptedOutput JSON serialization must be canonical"
                    );
                }
            }
        }
    }
});
