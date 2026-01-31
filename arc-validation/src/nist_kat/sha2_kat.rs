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
                    hex::encode(&result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-224 KAT
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
                    hex::encode(&result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-384 KAT
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
                    hex::encode(&result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-512 KAT
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
                    hex::encode(&result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-512/224 KAT
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
                    hex::encode(&result),
                    hex::encode(&expected_hash)
                ),
            });
        }
    }
    Ok(())
}

/// Run SHA-512/256 KAT
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
                    hex::encode(&result),
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
}
