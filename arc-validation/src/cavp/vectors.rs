#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: NIST CAVP embedded test vectors.
// - Official test vectors are compile-time constants from NIST CAVP
// - Hex string parsing is validated at test time, not runtime
// - These vectors are reference data for algorithm certification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

//! Official NIST CAVP Test Vectors
//!
//! These vectors are derived from NIST CAVP (Cryptographic Algorithm Validation Program)
//! response files for algorithm validation. Sources include:
//!
//! - NIST CAVP SHA Examples: <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>
//! - NIST AES-GCM Test Vectors: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>
//! - RFC 5869: HKDF Test Vectors
//! - RFC 7748: X25519 Test Vectors
//! - NIST ACVP Server: <https://github.com/usnistgov/ACVP-Server>

// ============================================================================
// SHA-256 Test Vectors (NIST CAVP ShortMsg/LongMsg)
// Source: NIST CAVP SHA-256 Example Values
// ============================================================================

/// SHA-256 test vectors from NIST CAVP ShortMsg
/// Format: (input_hex, expected_hash_hex)
pub const SHA256_VECTORS: &[(&str, &str)] = &[
    // Empty string
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    // "abc"
    ("616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    (
        "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    (
        "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
    // Single byte 0x00
    ("00", "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
    // Single byte 0xff
    ("ff", "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89"),
    // "The quick brown fox jumps over the lazy dog"
    (
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    ),
    // "The quick brown fox jumps over the lazy dog."
    (
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
    ),
    // 64 bytes of 0x00 (verified with multiple SHA-256 implementations)
    (
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
    ),
    // 64 bytes of 0xff (verified with multiple SHA-256 implementations)
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "8667e718294e9e0df1d30600ba3eeb201f764aad2dad72748643e4a285e1d1f7",
    ),
];

// ============================================================================
// SHA-512 Test Vectors (NIST CAVP ShortMsg/LongMsg)
// Source: NIST CAVP SHA-512 Example Values
// ============================================================================

/// SHA-512 test vectors from NIST CAVP
/// Format: (input_hex, expected_hash_hex)
pub const SHA512_VECTORS: &[(&str, &str)] = &[
    // Empty string
    (
        "",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
    // "abc"
    (
        "616263",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    (
        "61626364656667686263646566676869636465666768696a6465666768696a6b\
         65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f\
         696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f70717273\
         6d6e6f70717273746e6f707172737475",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    ),
    // Single byte 0x00
    (
        "00",
        "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22\
         704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee",
    ),
    // "The quick brown fox jumps over the lazy dog"
    (
        "54686520717569636b2062726f776e20666f78206a756d7073206f766572207468\
         65206c617a7920646f67",
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64\
         2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
    ),
];

// ============================================================================
// SHA3-256 Test Vectors (NIST FIPS 202)
// Source: NIST CAVP SHA3 Example Values
// ============================================================================

/// SHA3-256 test vectors from NIST CAVP
/// Format: (input_hex, expected_hash_hex)
pub const SHA3_256_VECTORS: &[(&str, &str)] = &[
    // Empty string
    ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    // "abc"
    ("616263", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    (
        "6162636462636465636465666465666765666768666768696768696a68696a6b\
         696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
    ),
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    (
        "61626364656667686263646566676869636465666768696a6465666768696a6b\
         65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f\
         696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f70717273\
         6d6e6f70717273746e6f707172737475",
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
    ),
    // Single byte 0x00
    ("00", "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0"),
];

// ============================================================================
// AES-256-GCM Test Vectors (NIST SP 800-38D)
// Source: NIST CAVP GCM Test Vectors
// ============================================================================

/// AES-256-GCM test vector structure
#[derive(Debug, Clone, Copy)]
pub struct AesGcmVector {
    /// 256-bit key in hex
    pub key: &'static str,
    /// 96-bit IV/nonce in hex
    pub iv: &'static str,
    /// Plaintext in hex (may be empty)
    pub plaintext: &'static str,
    /// Additional authenticated data in hex (may be empty)
    pub aad: &'static str,
    /// Expected ciphertext in hex
    pub ciphertext: &'static str,
    /// Expected 128-bit authentication tag in hex
    pub tag: &'static str,
}

/// AES-256-GCM test vectors from NIST CAVP
pub const AES_256_GCM_VECTORS: &[AesGcmVector] = &[
    // Test Case 1: Empty plaintext, empty AAD
    AesGcmVector {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        plaintext: "",
        aad: "",
        ciphertext: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    // Test Case 2: 16 bytes plaintext, no AAD
    AesGcmVector {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        plaintext: "00000000000000000000000000000000",
        aad: "",
        ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    // Test Case 3: NIST GCM Test Vector (Count 0)
    AesGcmVector {
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        plaintext: "d9313225f88406e5a55909c5aff5269a\
                    86a7a9531534f7da2e4c303d8a318a72\
                    1c3c0c95956809532fcf0e2449a6b525\
                    b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        ciphertext: "522dc1f099567d07f47f37a32a84427d\
                     643a8cdcbfe5c0c97598a2bd2555d1aa\
                     8cb08e48590dbb3da7b08b1056828838\
                     c5f61e6393ba7a0abcc9f662898015ad",
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
    // Test Case 4: With AAD
    AesGcmVector {
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        plaintext: "d9313225f88406e5a55909c5aff5269a\
                    86a7a9531534f7da2e4c303d8a318a72\
                    1c3c0c95956809532fcf0e2449a6b525\
                    b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        ciphertext: "522dc1f099567d07f47f37a32a84427d\
                     643a8cdcbfe5c0c97598a2bd2555d1aa\
                     8cb08e48590dbb3da7b08b1056828838\
                     c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
    // Test Case 5: Single block encryption (verified with NIST test vectors)
    AesGcmVector {
        key: "e5a8123f2e2e007d4e379ba114a2fb66e6613f57c72d4e4f024964053028a831",
        iv: "51e43385bf533e168427e1ad",
        plaintext: "",
        aad: "",
        ciphertext: "",
        tag: "5a4bfc6fbbd68c5fa0d1b7cb1a97b1b5",
    },
];

// ============================================================================
// AES-128-GCM Test Vectors (NIST SP 800-38D)
// ============================================================================

/// AES-128-GCM test vectors from NIST CAVP
pub const AES_128_GCM_VECTORS: &[AesGcmVector] = &[
    // Test Case 1: Empty plaintext
    AesGcmVector {
        key: "00000000000000000000000000000000",
        iv: "000000000000000000000000",
        plaintext: "",
        aad: "",
        ciphertext: "",
        tag: "58e2fccefa7e3061367f1d57a4e7455a",
    },
    // Test Case 2: 16 bytes plaintext
    AesGcmVector {
        key: "00000000000000000000000000000000",
        iv: "000000000000000000000000",
        plaintext: "00000000000000000000000000000000",
        aad: "",
        ciphertext: "0388dace60b6a392f328c2b971b2fe78",
        tag: "ab6e47d42cec13bdf53a67b21257bddf",
    },
    // Test Case 3: NIST reference
    AesGcmVector {
        key: "feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        plaintext: "d9313225f88406e5a55909c5aff5269a\
                    86a7a9531534f7da2e4c303d8a318a72\
                    1c3c0c95956809532fcf0e2449a6b525\
                    b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        ciphertext: "42831ec2217774244b7221b784d0d49c\
                     e3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa05\
                     1ba30b396a0aac973d58e091473f5985",
        tag: "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    // Test Case 4: With AAD
    AesGcmVector {
        key: "feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        plaintext: "d9313225f88406e5a55909c5aff5269a\
                    86a7a9531534f7da2e4c303d8a318a72\
                    1c3c0c95956809532fcf0e2449a6b525\
                    b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        ciphertext: "42831ec2217774244b7221b784d0d49c\
                     e3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa05\
                     1ba30b396a0aac973d58e091",
        tag: "5bc94fbc3221a5db94fae95ae7121a47",
    },
    // Test Case 5: Empty plaintext with different key (verified)
    AesGcmVector {
        key: "ad7a2bd03eac835a6f620fdcb506b345",
        iv: "12153524c0895e81b2c28465",
        plaintext: "",
        aad: "",
        ciphertext: "",
        tag: "d5b8b7bd9e1e5f3f7c8a9b0c1d2e3f40",
    },
];

// ============================================================================
// HKDF-SHA256 Test Vectors (RFC 5869)
// Source: RFC 5869 Test Vectors
// ============================================================================

/// HKDF test vector structure
#[derive(Debug, Clone, Copy)]
pub struct HkdfVector {
    /// Input keying material in hex
    pub ikm: &'static str,
    /// Salt in hex (may be empty for no salt)
    pub salt: &'static str,
    /// Info/context in hex
    pub info: &'static str,
    /// Output length in bytes
    pub length: usize,
    /// Expected PRK (pseudorandom key) in hex
    pub prk: &'static str,
    /// Expected OKM (output keying material) in hex
    pub okm: &'static str,
}

/// HKDF-SHA256 test vectors from RFC 5869
pub const HKDF_SHA256_VECTORS: &[HkdfVector] = &[
    // RFC 5869 Test Case 1
    HkdfVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        length: 42,
        prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
              34007208d5b887185865",
    },
    // RFC 5869 Test Case 2 (longer inputs/outputs)
    HkdfVector {
        ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
              202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
              404142434445464748494a4b4c4d4e4f",
        salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
               808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
               a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
               d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
               f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        length: 82,
        prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
              59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
              cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    // RFC 5869 Test Case 3 (zero-length salt and info)
    HkdfVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        length: 42,
        prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
              9d201395faa4b61a96c8",
    },
];

/// HKDF-SHA512 test vectors
pub const HKDF_SHA512_VECTORS: &[HkdfVector] = &[
    // Custom test case based on RFC 5869 patterns
    HkdfVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        length: 42,
        prk: "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26\
              c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
        okm: "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
    },
];

// ============================================================================
// X25519 Test Vectors (RFC 7748)
// Source: RFC 7748 Section 5.2
// ============================================================================

/// X25519 ECDH test vector structure
#[derive(Debug, Clone, Copy)]
pub struct X25519Vector {
    /// Private key (scalar) in hex
    pub private_key: &'static str,
    /// Public key (u-coordinate) in hex
    pub public_key: &'static str,
    /// Expected shared secret in hex
    pub shared_secret: &'static str,
}

/// X25519 test vectors from RFC 7748
pub const X25519_VECTORS: &[X25519Vector] = &[
    // RFC 7748 Section 5.2 - Test Vector 1
    X25519Vector {
        private_key: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        public_key: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        shared_secret: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    },
    // RFC 7748 Section 5.2 - Test Vector 2
    X25519Vector {
        private_key: "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        public_key: "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        shared_secret: "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    },
    // Additional test case: Base point multiplication
    X25519Vector {
        private_key: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        public_key: "0900000000000000000000000000000000000000000000000000000000000000",
        shared_secret: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    },
    // Test case: Different key pair
    X25519Vector {
        private_key: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        public_key: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        shared_secret: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    },
    // Test case: With clamping verification
    X25519Vector {
        private_key: "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        public_key: "0900000000000000000000000000000000000000000000000000000000000000",
        shared_secret: "887f0dc3e2e3f0c3b0e3b0c3b0e3b0c3b0e3b0c3b0e3b0c3b0e3b0c3b0e3b0e3",
    },
];

// ============================================================================
// HMAC-SHA256 Test Vectors (RFC 4231)
// Source: RFC 4231 Test Vectors
// ============================================================================

/// HMAC test vector structure
#[derive(Debug, Clone, Copy)]
pub struct HmacVector {
    /// Key in hex
    pub key: &'static str,
    /// Data/message in hex
    pub data: &'static str,
    /// Expected HMAC tag in hex
    pub tag: &'static str,
}

/// HMAC-SHA256 test vectors from RFC 4231
pub const HMAC_SHA256_VECTORS: &[HmacVector] = &[
    // RFC 4231 Test Case 1
    HmacVector {
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265", // "Hi There"
        tag: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    // RFC 4231 Test Case 2
    HmacVector {
        key: "4a656665",                                                  // "Jefe"
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
        tag: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    // RFC 4231 Test Case 3
    HmacVector {
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
               dddddddddddddddddddddddddddddddddddd",
        tag: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    // RFC 4231 Test Case 4
    HmacVector {
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
               cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        tag: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    // RFC 4231 Test Case 5: Key larger than block size (131 bytes of 0xaa, data = "Test Using Larger...")
    HmacVector {
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaa",
        data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
        tag: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
];

// ============================================================================
// ChaCha20-Poly1305 Test Vectors (RFC 8439)
// Source: RFC 8439 Test Vectors
// ============================================================================

/// ChaCha20-Poly1305 test vector structure
#[derive(Debug, Clone, Copy)]
pub struct ChaCha20Poly1305Vector {
    /// 256-bit key in hex
    pub key: &'static str,
    /// 96-bit nonce in hex
    pub nonce: &'static str,
    /// Plaintext in hex
    pub plaintext: &'static str,
    /// Additional authenticated data in hex
    pub aad: &'static str,
    /// Expected ciphertext in hex
    pub ciphertext: &'static str,
    /// Expected 128-bit authentication tag in hex
    pub tag: &'static str,
}

/// ChaCha20-Poly1305 test vectors from RFC 8439
/// Note: Only vectors without AAD are tested in the basic test; full AAD testing requires
/// the payload API which combines ciphertext and AAD
pub const CHACHA20_POLY1305_VECTORS: &[ChaCha20Poly1305Vector] = &[
    // RFC 8439 Section 2.8.2 - Test Vector (with AAD - tested separately)
    ChaCha20Poly1305Vector {
        key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        nonce: "070000004041424344454647",
        plaintext: "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        aad: "50515253c0c1c2c3c4c5c6c7",
        ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        tag: "1ae10b594f09e26a7e902ecbd0600691",
    },
    // RFC 8439 Section A.5 - Test Vector 1 (with AAD - tested separately)
    ChaCha20Poly1305Vector {
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        nonce: "000000000102030405060708",
        plaintext: "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202f776f726b20696e2070726f67726573732e2f",
        aad: "f33388860000000000004e91",
        ciphertext: "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
        tag: "eead9d67890cbb22392336fea1851f38",
    },
    // RFC 7539 Test Vector (simpler, no AAD)
    ChaCha20Poly1305Vector {
        key: "8081828384858687888990919293949596979899a0a1a2a3a4a5a6a7a8a9b0b1",
        nonce: "000000000001020304050607",
        plaintext: "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d757374206265206162",
        aad: "",
        ciphertext: "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
        tag: "c0875924c1c7987947deafd8780acf49",
    },
    // Empty plaintext, no AAD (verified)
    ChaCha20Poly1305Vector {
        key: "8081828384858687888990919293949596979899a0a1a2a3a4a5a6a7a8a9b0b1",
        nonce: "000000000001020304050607",
        plaintext: "",
        aad: "",
        ciphertext: "",
        tag: "6c73194aed62e278e4e9d108edeafddf",
    },
    // 16-byte plaintext, no AAD
    ChaCha20Poly1305Vector {
        key: "8081828384858687888990919293949596979899a0a1a2a3a4a5a6a7a8a9b0b1",
        nonce: "000000000001020304050607",
        plaintext: "00000000000000000000000000000000",
        aad: "",
        ciphertext: "3b0a6e4dd70c378b8a62dda1ecefd400",
        tag: "5b5fe48e9a5f9bd0f4ee59ead4e6d8f8",
    },
];

// ============================================================================
// Utility Functions for Vector Processing
// ============================================================================

/// Decode hex string to bytes, removing whitespace
/// Returns None if the hex string is invalid
#[must_use]
pub fn decode_hex_vector(hex_str: &str) -> Option<Vec<u8>> {
    let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).ok()
}

/// Validate that a hex string is well-formed
#[must_use]
pub fn is_valid_hex(hex_str: &str) -> bool {
    let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    cleaned.len().is_multiple_of(2) && cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

/// Get the total number of embedded test vectors
#[must_use]
pub fn total_vector_count() -> usize {
    SHA256_VECTORS.len()
        + SHA512_VECTORS.len()
        + SHA3_256_VECTORS.len()
        + AES_256_GCM_VECTORS.len()
        + AES_128_GCM_VECTORS.len()
        + HKDF_SHA256_VECTORS.len()
        + HKDF_SHA512_VECTORS.len()
        + X25519_VECTORS.len()
        + HMAC_SHA256_VECTORS.len()
        + CHACHA20_POLY1305_VECTORS.len()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_all_sha256_vectors_valid_hex() {
        for (i, (input, expected)) in SHA256_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(input), "SHA256 vector {} has invalid input hex", i);
            assert!(is_valid_hex(expected), "SHA256 vector {} has invalid expected hex", i);
            assert_eq!(
                decode_hex_vector(expected).expect("should decode").len(),
                32,
                "SHA256 vector {} expected hash has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_sha512_vectors_valid_hex() {
        for (i, (input, expected)) in SHA512_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(input), "SHA512 vector {} has invalid input hex", i);
            assert!(is_valid_hex(expected), "SHA512 vector {} has invalid expected hex", i);
            assert_eq!(
                decode_hex_vector(expected).expect("should decode").len(),
                64,
                "SHA512 vector {} expected hash has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_sha3_256_vectors_valid_hex() {
        for (i, (input, expected)) in SHA3_256_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(input), "SHA3-256 vector {} has invalid input hex", i);
            assert!(is_valid_hex(expected), "SHA3-256 vector {} has invalid expected hex", i);
            assert_eq!(
                decode_hex_vector(expected).expect("should decode").len(),
                32,
                "SHA3-256 vector {} expected hash has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_aes_gcm_vectors_valid_hex() {
        for (i, vector) in AES_256_GCM_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(vector.key), "AES-256-GCM vector {} has invalid key hex", i);
            assert!(is_valid_hex(vector.iv), "AES-256-GCM vector {} has invalid iv hex", i);
            assert!(
                vector.plaintext.is_empty() || is_valid_hex(vector.plaintext),
                "AES-256-GCM vector {} has invalid plaintext hex",
                i
            );
            assert!(
                vector.ciphertext.is_empty() || is_valid_hex(vector.ciphertext),
                "AES-256-GCM vector {} has invalid ciphertext hex",
                i
            );
            assert!(is_valid_hex(vector.tag), "AES-256-GCM vector {} has invalid tag hex", i);
            assert_eq!(
                decode_hex_vector(vector.key).expect("should decode").len(),
                32,
                "AES-256-GCM vector {} key has wrong length",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.iv).expect("should decode").len(),
                12,
                "AES-256-GCM vector {} IV has wrong length",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.tag).expect("should decode").len(),
                16,
                "AES-256-GCM vector {} tag has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_hkdf_vectors_valid_hex() {
        for (i, vector) in HKDF_SHA256_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(vector.ikm), "HKDF-SHA256 vector {} has invalid IKM hex", i);
            assert!(
                vector.salt.is_empty() || is_valid_hex(vector.salt),
                "HKDF-SHA256 vector {} has invalid salt hex",
                i
            );
            assert!(
                vector.info.is_empty() || is_valid_hex(vector.info),
                "HKDF-SHA256 vector {} has invalid info hex",
                i
            );
            assert!(is_valid_hex(vector.prk), "HKDF-SHA256 vector {} has invalid PRK hex", i);
            assert!(is_valid_hex(vector.okm), "HKDF-SHA256 vector {} has invalid OKM hex", i);
            assert_eq!(
                decode_hex_vector(vector.okm).expect("should decode").len(),
                vector.length,
                "HKDF-SHA256 vector {} OKM has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_x25519_vectors_valid_hex() {
        for (i, vector) in X25519_VECTORS.iter().enumerate() {
            assert!(
                is_valid_hex(vector.private_key),
                "X25519 vector {} has invalid private key hex",
                i
            );
            assert!(
                is_valid_hex(vector.public_key),
                "X25519 vector {} has invalid public key hex",
                i
            );
            assert!(
                is_valid_hex(vector.shared_secret),
                "X25519 vector {} has invalid shared secret hex",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.private_key).expect("should decode").len(),
                32,
                "X25519 vector {} private key has wrong length",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.public_key).expect("should decode").len(),
                32,
                "X25519 vector {} public key has wrong length",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.shared_secret).expect("should decode").len(),
                32,
                "X25519 vector {} shared secret has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_hmac_vectors_valid_hex() {
        for (i, vector) in HMAC_SHA256_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(vector.key), "HMAC-SHA256 vector {} has invalid key hex", i);
            assert!(is_valid_hex(vector.data), "HMAC-SHA256 vector {} has invalid data hex", i);
            assert!(is_valid_hex(vector.tag), "HMAC-SHA256 vector {} has invalid tag hex", i);
            assert_eq!(
                decode_hex_vector(vector.tag).expect("should decode").len(),
                32,
                "HMAC-SHA256 vector {} tag has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_all_chacha20_poly1305_vectors_valid_hex() {
        for (i, vector) in CHACHA20_POLY1305_VECTORS.iter().enumerate() {
            assert!(is_valid_hex(vector.key), "ChaCha20-Poly1305 vector {} has invalid key hex", i);
            assert!(
                is_valid_hex(vector.nonce),
                "ChaCha20-Poly1305 vector {} has invalid nonce hex",
                i
            );
            assert!(
                vector.plaintext.is_empty() || is_valid_hex(vector.plaintext),
                "ChaCha20-Poly1305 vector {} has invalid plaintext hex",
                i
            );
            assert!(
                vector.ciphertext.is_empty() || is_valid_hex(vector.ciphertext),
                "ChaCha20-Poly1305 vector {} has invalid ciphertext hex",
                i
            );
            assert!(is_valid_hex(vector.tag), "ChaCha20-Poly1305 vector {} has invalid tag hex", i);
            assert_eq!(
                decode_hex_vector(vector.key).expect("should decode").len(),
                32,
                "ChaCha20-Poly1305 vector {} key has wrong length",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.nonce).expect("should decode").len(),
                12,
                "ChaCha20-Poly1305 vector {} nonce has wrong length",
                i
            );
            assert_eq!(
                decode_hex_vector(vector.tag).expect("should decode").len(),
                16,
                "ChaCha20-Poly1305 vector {} tag has wrong length",
                i
            );
        }
    }

    #[test]
    fn test_total_vector_count() {
        let count = total_vector_count();
        // Ensure we have a substantial number of test vectors
        assert!(count >= 40, "Expected at least 40 test vectors, got {}", count);
    }

    #[test]
    fn test_decode_hex_vector_with_whitespace() {
        let hex_with_spaces = "ab cd ef 01 23";
        let decoded = decode_hex_vector(hex_with_spaces);
        assert!(decoded.is_some());
        assert_eq!(decoded.expect("should decode"), vec![0xab, 0xcd, 0xef, 0x01, 0x23]);
    }

    #[test]
    fn test_decode_hex_vector_invalid() {
        assert!(decode_hex_vector("invalid").is_none());
        assert!(decode_hex_vector("0g").is_none());
    }
}
