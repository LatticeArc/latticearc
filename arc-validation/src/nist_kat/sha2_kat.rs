#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]

//! SHA-2 Known Answer Tests
//!
//! Test vectors from FIPS 180-4 (Secure Hash Standard)
//! Source: NIST CAVP test vectors for SHA-2 family
//!
//! ## Algorithms Tested
//! - SHA-224: 224-bit output
//! - SHA-256: 256-bit output
//! - SHA-384: 384-bit output
//! - SHA-512: 512-bit output
//! - SHA-512/224: 224-bit output (SHA-512 truncated)
//! - SHA-512/256: 256-bit output (SHA-512 truncated)

use super::{NistKatError, decode_hex};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

/// Test vector for SHA-2
pub struct Sha2TestVector {
    pub test_name: &'static str,
    pub message: &'static str,
    pub expected_hash: &'static str,
}

/// SHA-256 test vectors from NIST
pub const SHA256_VECTORS: &[Sha2TestVector] = &[
    // Test Case 1: Empty string
    Sha2TestVector {
        test_name: "SHA-256-KAT-1",
        message: "",
        expected_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    // Test Case 2: "abc"
    Sha2TestVector {
        test_name: "SHA-256-KAT-2",
        message: "616263", // "abc"
        expected_hash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    // Test Case 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    Sha2TestVector {
        test_name: "SHA-256-KAT-3",
        message: "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
        expected_hash: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
    // Test Case 4: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    Sha2TestVector {
        test_name: "SHA-256-KAT-4",
        message: "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475",
        expected_hash: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    },
];

/// SHA-224 test vectors from NIST
pub const SHA224_VECTORS: &[Sha2TestVector] = &[
    // Test Case 1: Empty string
    Sha2TestVector {
        test_name: "SHA-224-KAT-1",
        message: "",
        expected_hash: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    },
    // Test Case 2: "abc"
    Sha2TestVector {
        test_name: "SHA-224-KAT-2",
        message: "616263",
        expected_hash: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    },
];

/// SHA-384 test vectors from NIST
pub const SHA384_VECTORS: &[Sha2TestVector] = &[
    // Test Case 1: Empty string
    Sha2TestVector {
        test_name: "SHA-384-KAT-1",
        message: "",
        expected_hash: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    // Test Case 2: "abc"
    Sha2TestVector {
        test_name: "SHA-384-KAT-2",
        message: "616263",
        expected_hash: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    },
];

/// SHA-512 test vectors from NIST
pub const SHA512_VECTORS: &[Sha2TestVector] = &[
    // Test Case 1: Empty string
    Sha2TestVector {
        test_name: "SHA-512-KAT-1",
        message: "",
        expected_hash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    // Test Case 2: "abc"
    Sha2TestVector {
        test_name: "SHA-512-KAT-2",
        message: "616263",
        expected_hash: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    },
];

/// SHA-512/224 test vectors
pub const SHA512_224_VECTORS: &[Sha2TestVector] = &[
    // Test Case 1: Empty string
    Sha2TestVector {
        test_name: "SHA-512/224-KAT-1",
        message: "",
        expected_hash: "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    },
    // Test Case 2: "abc"
    Sha2TestVector {
        test_name: "SHA-512/224-KAT-2",
        message: "616263",
        expected_hash: "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    },
];

/// SHA-512/256 test vectors
pub const SHA512_256_VECTORS: &[Sha2TestVector] = &[
    // Test Case 1: Empty string
    Sha2TestVector {
        test_name: "SHA-512/256-KAT-1",
        message: "",
        expected_hash: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    },
    // Test Case 2: "abc"
    Sha2TestVector {
        test_name: "SHA-512/256-KAT-2",
        message: "616263",
        expected_hash: "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    },
];

/// Run SHA-256 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_sha256_kat() -> Result<(), NistKatError> {
    for vector in SHA256_VECTORS {
        let message = decode_hex(vector.message)?;
        let expected_hash = decode_hex(vector.expected_hash)?;

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-256".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-224 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_sha224_kat() -> Result<(), NistKatError> {
    for vector in SHA224_VECTORS {
        let message = decode_hex(vector.message)?;
        let expected_hash = decode_hex(vector.expected_hash)?;

        let mut hasher = Sha224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-224".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-384 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_sha384_kat() -> Result<(), NistKatError> {
    for vector in SHA384_VECTORS {
        let message = decode_hex(vector.message)?;
        let expected_hash = decode_hex(vector.expected_hash)?;

        let mut hasher = Sha384::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-384".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-512 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_sha512_kat() -> Result<(), NistKatError> {
    for vector in SHA512_VECTORS {
        let message = decode_hex(vector.message)?;
        let expected_hash = decode_hex(vector.expected_hash)?;

        let mut hasher = Sha512::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-512".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-512/224 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_sha512_224_kat() -> Result<(), NistKatError> {
    for vector in SHA512_224_VECTORS {
        let message = decode_hex(vector.message)?;
        let expected_hash = decode_hex(vector.expected_hash)?;

        let mut hasher = Sha512_224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-512/224".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-512/256 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_sha512_256_kat() -> Result<(), NistKatError> {
    for vector in SHA512_256_VECTORS {
        let message = decode_hex(vector.message)?;
        let expected_hash = decode_hex(vector.expected_hash)?;

        let mut hasher = Sha512_256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-512/256".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Happy-path KAT tests (all 6 variants)
    // =========================================================================

    #[test]
    fn test_sha256_kat() {
        let result = run_sha256_kat();
        assert!(result.is_ok(), "SHA-256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_sha224_kat() {
        let result = run_sha224_kat();
        assert!(result.is_ok(), "SHA-224 KAT failed: {:?}", result);
    }

    #[test]
    fn test_sha384_kat() {
        let result = run_sha384_kat();
        assert!(result.is_ok(), "SHA-384 KAT failed: {:?}", result);
    }

    #[test]
    fn test_sha512_kat() {
        let result = run_sha512_kat();
        assert!(result.is_ok(), "SHA-512 KAT failed: {:?}", result);
    }

    #[test]
    fn test_sha512_224_kat() {
        let result = run_sha512_224_kat();
        assert!(result.is_ok(), "SHA-512/224 KAT failed: {:?}", result);
    }

    #[test]
    fn test_sha512_256_kat() {
        let result = run_sha512_256_kat();
        assert!(result.is_ok(), "SHA-512/256 KAT failed: {:?}", result);
    }

    // =========================================================================
    // Error path: hash mismatch detection for each SHA-2 variant
    //
    // These tests replicate the production function logic with an intentionally
    // wrong expected hash to exercise the error construction code path that
    // produces NistKatError::TestFailed.
    // =========================================================================

    #[allow(dead_code)]
    fn verify_sha256_mismatch_error(
        message_hex: &str,
        wrong_expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let message = decode_hex(message_hex)?;
        let expected_hash = decode_hex(wrong_expected_hex)?;

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-256".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn test_sha256_mismatch_returns_error() {
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_sha256_mismatch_error("616263", wrong_hash, "mismatch-test");
        assert!(result.is_err());
        if let Err(NistKatError::TestFailed { algorithm, test_name, message }) = result {
            assert_eq!(algorithm, "SHA-256");
            assert_eq!(test_name, "mismatch-test");
            assert!(message.contains("Hash mismatch"));
            assert!(message.contains("got "));
            assert!(message.contains("expected "));
        }
    }

    #[allow(dead_code)]
    fn verify_sha224_mismatch_error(
        message_hex: &str,
        wrong_expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let message = decode_hex(message_hex)?;
        let expected_hash = decode_hex(wrong_expected_hex)?;

        let mut hasher = Sha224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-224".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn test_sha224_mismatch_returns_error() {
        let wrong_hash = "00000000000000000000000000000000000000000000000000000000";
        let result = verify_sha224_mismatch_error("616263", wrong_hash, "mismatch-224");
        assert!(result.is_err());
        if let Err(NistKatError::TestFailed { algorithm, test_name, message }) = result {
            assert_eq!(algorithm, "SHA-224");
            assert_eq!(test_name, "mismatch-224");
            assert!(message.contains("Hash mismatch"));
        }
    }

    #[allow(dead_code)]
    fn verify_sha384_mismatch_error(
        message_hex: &str,
        wrong_expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let message = decode_hex(message_hex)?;
        let expected_hash = decode_hex(wrong_expected_hex)?;

        let mut hasher = Sha384::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-384".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn test_sha384_mismatch_returns_error() {
        let wrong_hash = "000000000000000000000000000000000000000000000000\
                          000000000000000000000000000000000000000000000000";
        let result = verify_sha384_mismatch_error("616263", wrong_hash, "mismatch-384");
        assert!(result.is_err());
        if let Err(NistKatError::TestFailed { algorithm, test_name, message }) = result {
            assert_eq!(algorithm, "SHA-384");
            assert_eq!(test_name, "mismatch-384");
            assert!(message.contains("Hash mismatch"));
        }
    }

    #[allow(dead_code)]
    fn verify_sha512_mismatch_error(
        message_hex: &str,
        wrong_expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let message = decode_hex(message_hex)?;
        let expected_hash = decode_hex(wrong_expected_hex)?;

        let mut hasher = Sha512::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-512".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn test_sha512_mismatch_returns_error() {
        let wrong_hash = "00000000000000000000000000000000\
                          00000000000000000000000000000000\
                          00000000000000000000000000000000\
                          00000000000000000000000000000000";
        let result = verify_sha512_mismatch_error("616263", wrong_hash, "mismatch-512");
        assert!(result.is_err());
        if let Err(NistKatError::TestFailed { algorithm, test_name, message }) = result {
            assert_eq!(algorithm, "SHA-512");
            assert_eq!(test_name, "mismatch-512");
            assert!(message.contains("Hash mismatch"));
        }
    }

    #[allow(dead_code)]
    fn verify_sha512_224_mismatch_error(
        message_hex: &str,
        wrong_expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let message = decode_hex(message_hex)?;
        let expected_hash = decode_hex(wrong_expected_hex)?;

        let mut hasher = Sha512_224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-512/224".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn test_sha512_224_mismatch_returns_error() {
        let wrong_hash = "00000000000000000000000000000000000000000000000000000000";
        let result = verify_sha512_224_mismatch_error("616263", wrong_hash, "mismatch-512-224");
        assert!(result.is_err());
        if let Err(NistKatError::TestFailed { algorithm, test_name, message }) = result {
            assert_eq!(algorithm, "SHA-512/224");
            assert_eq!(test_name, "mismatch-512-224");
            assert!(message.contains("Hash mismatch"));
        }
    }

    #[allow(dead_code)]
    fn verify_sha512_256_mismatch_error(
        message_hex: &str,
        wrong_expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let message = decode_hex(message_hex)?;
        let expected_hash = decode_hex(wrong_expected_hex)?;

        let mut hasher = Sha512_256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        if result.as_slice() != expected_hash.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "SHA-512/256".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "Hash mismatch: got {}, expected {}",
                    hex::encode(result),
                    hex::encode(&expected_hash)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn test_sha512_256_mismatch_returns_error() {
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_sha512_256_mismatch_error("616263", wrong_hash, "mismatch-512-256");
        assert!(result.is_err());
        if let Err(NistKatError::TestFailed { algorithm, test_name, message }) = result {
            assert_eq!(algorithm, "SHA-512/256");
            assert_eq!(test_name, "mismatch-512-256");
            assert!(message.contains("Hash mismatch"));
        }
    }

    // =========================================================================
    // Error path: hex decoding errors propagated through the ? operator
    // =========================================================================

    #[test]
    fn test_sha256_mismatch_hex_error_in_message() {
        let result = verify_sha256_mismatch_error(
            "ZZZZ",
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855",
            "hex-err-msg",
        );
        assert!(result.is_err());
        if let Err(NistKatError::HexError(msg)) = result {
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_sha256_mismatch_hex_error_in_expected() {
        let result = verify_sha256_mismatch_error("616263", "ZZZZ", "hex-err-expected");
        assert!(result.is_err());
        if let Err(NistKatError::HexError(msg)) = result {
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_sha224_mismatch_hex_error_in_message() {
        let result = verify_sha224_mismatch_error(
            "XY",
            "d14a028c2a3a2bc9476102bb288234c4\
             15a2b01f828ea62ac5b3e42f",
            "hex-err",
        );
        assert!(result.is_err());
        if let Err(NistKatError::HexError(msg)) = result {
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_sha384_mismatch_hex_error_in_message() {
        let result = verify_sha384_mismatch_error(
            "GG",
            "38b060a751ac96384cd9327eb1b1e36a\
             21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
            "hex-err",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sha512_mismatch_hex_error_in_message() {
        let result = verify_sha512_mismatch_error(
            "QQ",
            "cf83e1357eefb8bdf1542850d66d8007\
             d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f\
             63b931bd47417a81a538327af927da3e",
            "hex-err",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sha512_224_mismatch_hex_error_in_message() {
        let result = verify_sha512_224_mismatch_error(
            "!!",
            "6ed0dd02806fa89e25de060c19d3ac86\
             cabb87d6a0ddd05c333b84f4",
            "hex-err",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sha512_256_mismatch_hex_error_in_message() {
        let result = verify_sha512_256_mismatch_error(
            "$$",
            "c672b8d1ef56ed28ab87c3622c511406\
             9bdd3ad7b8f9737498d0c01ecef0967a",
            "hex-err",
        );
        assert!(result.is_err());
    }

    // =========================================================================
    // Test vector validation: fields, counts, and content
    // =========================================================================

    #[test]
    fn test_sha256_vector_count() {
        assert_eq!(SHA256_VECTORS.len(), 4);
    }

    #[test]
    fn test_sha224_vector_count() {
        assert_eq!(SHA224_VECTORS.len(), 2);
    }

    #[test]
    fn test_sha384_vector_count() {
        assert_eq!(SHA384_VECTORS.len(), 2);
    }

    #[test]
    fn test_sha512_vector_count() {
        assert_eq!(SHA512_VECTORS.len(), 2);
    }

    #[test]
    fn test_sha512_224_vector_count() {
        assert_eq!(SHA512_224_VECTORS.len(), 2);
    }

    #[test]
    fn test_sha512_256_vector_count() {
        assert_eq!(SHA512_256_VECTORS.len(), 2);
    }

    #[test]
    fn test_all_vectors_have_valid_hex_messages() {
        for v in SHA256_VECTORS {
            assert!(decode_hex(v.message).is_ok(), "bad hex in {}", v.test_name);
        }
        for v in SHA224_VECTORS {
            assert!(decode_hex(v.message).is_ok(), "bad hex in {}", v.test_name);
        }
        for v in SHA384_VECTORS {
            assert!(decode_hex(v.message).is_ok(), "bad hex in {}", v.test_name);
        }
        for v in SHA512_VECTORS {
            assert!(decode_hex(v.message).is_ok(), "bad hex in {}", v.test_name);
        }
        for v in SHA512_224_VECTORS {
            assert!(decode_hex(v.message).is_ok(), "bad hex in {}", v.test_name);
        }
        for v in SHA512_256_VECTORS {
            assert!(decode_hex(v.message).is_ok(), "bad hex in {}", v.test_name);
        }
    }

    #[test]
    fn test_all_vectors_have_valid_hex_expected_hashes() {
        for v in SHA256_VECTORS {
            assert!(
                decode_hex(v.expected_hash).is_ok(),
                "bad expected_hash hex in {}",
                v.test_name
            );
        }
        for v in SHA224_VECTORS {
            assert!(
                decode_hex(v.expected_hash).is_ok(),
                "bad expected_hash hex in {}",
                v.test_name
            );
        }
        for v in SHA384_VECTORS {
            assert!(
                decode_hex(v.expected_hash).is_ok(),
                "bad expected_hash hex in {}",
                v.test_name
            );
        }
        for v in SHA512_VECTORS {
            assert!(
                decode_hex(v.expected_hash).is_ok(),
                "bad expected_hash hex in {}",
                v.test_name
            );
        }
        for v in SHA512_224_VECTORS {
            assert!(
                decode_hex(v.expected_hash).is_ok(),
                "bad expected_hash hex in {}",
                v.test_name
            );
        }
        for v in SHA512_256_VECTORS {
            assert!(
                decode_hex(v.expected_hash).is_ok(),
                "bad expected_hash hex in {}",
                v.test_name
            );
        }
    }

    #[test]
    fn test_all_vectors_have_non_empty_test_names() {
        for v in SHA256_VECTORS {
            assert!(!v.test_name.is_empty());
        }
        for v in SHA224_VECTORS {
            assert!(!v.test_name.is_empty());
        }
        for v in SHA384_VECTORS {
            assert!(!v.test_name.is_empty());
        }
        for v in SHA512_VECTORS {
            assert!(!v.test_name.is_empty());
        }
        for v in SHA512_224_VECTORS {
            assert!(!v.test_name.is_empty());
        }
        for v in SHA512_256_VECTORS {
            assert!(!v.test_name.is_empty());
        }
    }

    #[test]
    fn test_sha256_expected_hash_length() {
        for v in SHA256_VECTORS {
            // SHA-256 produces 32 bytes = 64 hex chars
            assert_eq!(v.expected_hash.len(), 64, "{}", v.test_name);
        }
    }

    #[test]
    fn test_sha224_expected_hash_length() {
        for v in SHA224_VECTORS {
            // SHA-224 produces 28 bytes = 56 hex chars
            assert_eq!(v.expected_hash.len(), 56, "{}", v.test_name);
        }
    }

    #[test]
    fn test_sha384_expected_hash_length() {
        for v in SHA384_VECTORS {
            // SHA-384 produces 48 bytes = 96 hex chars
            assert_eq!(v.expected_hash.len(), 96, "{}", v.test_name);
        }
    }

    #[test]
    fn test_sha512_expected_hash_length() {
        for v in SHA512_VECTORS {
            // SHA-512 produces 64 bytes = 128 hex chars
            assert_eq!(v.expected_hash.len(), 128, "{}", v.test_name);
        }
    }

    #[test]
    fn test_sha512_224_expected_hash_length() {
        for v in SHA512_224_VECTORS {
            // SHA-512/224 produces 28 bytes = 56 hex chars
            assert_eq!(v.expected_hash.len(), 56, "{}", v.test_name);
        }
    }

    #[test]
    fn test_sha512_256_expected_hash_length() {
        for v in SHA512_256_VECTORS {
            // SHA-512/256 produces 32 bytes = 64 hex chars
            assert_eq!(v.expected_hash.len(), 64, "{}", v.test_name);
        }
    }

    // =========================================================================
    // Output length verification for each SHA-2 variant
    // =========================================================================

    #[test]
    fn test_sha224_output_is_28_bytes() {
        let mut h = Sha224::new();
        h.update(b"");
        assert_eq!(h.finalize().len(), 28);
    }

    #[test]
    fn test_sha256_output_is_32_bytes() {
        let mut h = Sha256::new();
        h.update(b"");
        assert_eq!(h.finalize().len(), 32);
    }

    #[test]
    fn test_sha384_output_is_48_bytes() {
        let mut h = Sha384::new();
        h.update(b"");
        assert_eq!(h.finalize().len(), 48);
    }

    #[test]
    fn test_sha512_output_is_64_bytes() {
        let mut h = Sha512::new();
        h.update(b"");
        assert_eq!(h.finalize().len(), 64);
    }

    #[test]
    fn test_sha512_224_output_is_28_bytes() {
        let mut h = Sha512_224::new();
        h.update(b"");
        assert_eq!(h.finalize().len(), 28);
    }

    #[test]
    fn test_sha512_256_output_is_32_bytes() {
        let mut h = Sha512_256::new();
        h.update(b"");
        assert_eq!(h.finalize().len(), 32);
    }

    // =========================================================================
    // Mismatch detection succeeds on correct vectors (no false positive)
    // =========================================================================

    #[test]
    fn test_sha256_correct_vector_returns_ok() {
        // Use "abc" vector (index 1)
        if let Some(v) = SHA256_VECTORS.get(1) {
            let result = verify_sha256_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha224_correct_vector_returns_ok() {
        if let Some(v) = SHA224_VECTORS.get(1) {
            let result = verify_sha224_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha384_correct_vector_returns_ok() {
        if let Some(v) = SHA384_VECTORS.get(1) {
            let result = verify_sha384_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha512_correct_vector_returns_ok() {
        if let Some(v) = SHA512_VECTORS.get(1) {
            let result = verify_sha512_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha512_224_correct_vector_returns_ok() {
        if let Some(v) = SHA512_224_VECTORS.get(1) {
            let result = verify_sha512_224_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha512_256_correct_vector_returns_ok() {
        if let Some(v) = SHA512_256_VECTORS.get(1) {
            let result = verify_sha512_256_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // Determinism: same input always produces same hash
    // =========================================================================

    #[test]
    fn test_sha256_deterministic() {
        let msg = decode_hex("deadbeef").ok();
        assert!(msg.is_some());
        let msg = msg.unwrap_or_default();
        let mut h1 = Sha256::new();
        h1.update(&msg);
        let r1 = h1.finalize();
        let mut h2 = Sha256::new();
        h2.update(&msg);
        let r2 = h2.finalize();
        assert_eq!(r1.as_slice(), r2.as_slice());
    }

    #[test]
    fn test_sha512_deterministic() {
        let msg = decode_hex("cafebabe").ok();
        assert!(msg.is_some());
        let msg = msg.unwrap_or_default();
        let mut h1 = Sha512::new();
        h1.update(&msg);
        let r1 = h1.finalize();
        let mut h2 = Sha512::new();
        h2.update(&msg);
        let r2 = h2.finalize();
        assert_eq!(r1.as_slice(), r2.as_slice());
    }

    // =========================================================================
    // Empty message vectors (first vector in each suite)
    // =========================================================================

    #[test]
    fn test_sha256_empty_message_vector() {
        if let Some(v) = SHA256_VECTORS.first() {
            assert_eq!(v.message, "");
            let result = verify_sha256_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha224_empty_message_vector() {
        if let Some(v) = SHA224_VECTORS.first() {
            assert_eq!(v.message, "");
            let result = verify_sha224_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha384_empty_message_vector() {
        if let Some(v) = SHA384_VECTORS.first() {
            assert_eq!(v.message, "");
            let result = verify_sha384_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha512_empty_message_vector() {
        if let Some(v) = SHA512_VECTORS.first() {
            assert_eq!(v.message, "");
            let result = verify_sha512_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha512_224_empty_message_vector() {
        if let Some(v) = SHA512_224_VECTORS.first() {
            assert_eq!(v.message, "");
            let result = verify_sha512_224_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_sha512_256_empty_message_vector() {
        if let Some(v) = SHA512_256_VECTORS.first() {
            assert_eq!(v.message, "");
            let result = verify_sha512_256_mismatch_error(v.message, v.expected_hash, v.test_name);
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // Error variant construction and Display coverage
    // =========================================================================

    #[test]
    fn test_nist_kat_error_test_failed_display() {
        let err = NistKatError::TestFailed {
            algorithm: "SHA-256".to_string(),
            test_name: "KAT-1".to_string(),
            message: "mismatch".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("SHA-256"));
        assert!(s.contains("KAT-1"));
        assert!(s.contains("mismatch"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_display() {
        let err = NistKatError::HexError("bad input".to_string());
        let s = format!("{err}");
        assert!(s.contains("Hex decode error"));
        assert!(s.contains("bad input"));
    }

    #[test]
    fn test_nist_kat_error_debug() {
        let err = NistKatError::TestFailed {
            algorithm: "SHA-384".to_string(),
            test_name: "KAT-2".to_string(),
            message: "wrong hash".to_string(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TestFailed"));
    }

    // =========================================================================
    // Incremental hashing produces same result as single update
    // =========================================================================

    #[test]
    fn test_sha256_incremental_vs_single_update() {
        let data = b"abcdefghij";

        let mut h1 = Sha256::new();
        h1.update(data);
        let r1 = h1.finalize();

        let mut h2 = Sha256::new();
        for &b in data {
            h2.update([b]);
        }
        let r2 = h2.finalize();

        assert_eq!(r1.as_slice(), r2.as_slice());
    }

    #[test]
    fn test_sha512_incremental_vs_single_update() {
        let data = b"abcdefghij";

        let mut h1 = Sha512::new();
        h1.update(data);
        let r1 = h1.finalize();

        let mut h2 = Sha512::new();
        for &b in data {
            h2.update([b]);
        }
        let r2 = h2.finalize();

        assert_eq!(r1.as_slice(), r2.as_slice());
    }

    // =========================================================================
    // Repeated KAT runs produce same outcome
    // =========================================================================

    #[test]
    fn test_repeated_kat_runs_all_variants() {
        for _ in 0..3 {
            assert!(run_sha224_kat().is_ok());
            assert!(run_sha256_kat().is_ok());
            assert!(run_sha384_kat().is_ok());
            assert!(run_sha512_kat().is_ok());
            assert!(run_sha512_224_kat().is_ok());
            assert!(run_sha512_256_kat().is_ok());
        }
    }
}
