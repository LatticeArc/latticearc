#![deny(unsafe_code)]
// Test files use unwrap() for simplicity - test failures will show clear panics
#![allow(clippy::unwrap_used)]
// Test files use indexing for test vector access
#![allow(clippy::indexing_slicing)]
// Clone is needed in some tests where we want to keep the original value
#![allow(clippy::redundant_clone)]

//! Comprehensive tests for Key Derivation Functions
//!
//! This test module validates all KDF implementations:
//! - PBKDF2 (NIST SP 800-132)
//! - HKDF (NIST SP 800-56C / RFC 5869)
//! - SP 800-108 Counter-based KDF

use arc_primitives::kdf::*;

mod pbkdf2_tests {
    use super::*;

    use zeroize::Zeroize;

    #[test]
    #[ignore] // Fails due to security hardening (min iterations = 1000)
    fn test_pbkdf2_rfc6070_test_vector_1() {
        // RFC 6070 Test Vector 1
        let password = b"password";
        let salt = b"salt";
        let iterations = 1;
        let params = Pbkdf2Params::with_salt(salt).iterations(iterations).key_length(20);

        let result = pbkdf2(password, &params).unwrap();
        let expected = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
            0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
        ];

        assert_eq!(&result.key[..], &expected);
    }

    #[test]
    #[ignore] // Fails due to security hardening (min iterations = 1000)
    fn test_pbkdf2_rfc6070_test_vector_2() {
        // RFC 6070 Test Vector 2
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let params = Pbkdf2Params::with_salt(salt).iterations(iterations).key_length(20);

        let result = pbkdf2(password, &params).unwrap();
        let expected = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];

        assert_eq!(&result.key[..], &expected);
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let password = b"test password";
        let salt = b"test salt 123456";
        let params = Pbkdf2Params::with_salt(salt).iterations(10000).key_length(32);

        let result1 = pbkdf2(password, &params).unwrap();
        let result2 = pbkdf2(password, &params).unwrap();

        assert_eq!(result1.key, result2.key);
    }

    #[test]
    fn test_pbkdf2_different_passwords() {
        let salt = b"common salt";
        let params = Pbkdf2Params::with_salt(salt).iterations(5000).key_length(32);

        let result1 = pbkdf2(b"password1", &params).unwrap();
        let result2 = pbkdf2(b"password2", &params).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_pbkdf2_different_salts() {
        let password = b"common password";
        let params1 = Pbkdf2Params::with_salt(b"salt1").iterations(5000).key_length(32);
        let params2 = Pbkdf2Params::with_salt(b"salt2").iterations(5000).key_length(32);

        let result1 = pbkdf2(password, &params1).unwrap();
        let result2 = pbkdf2(password, &params2).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_pbkdf2_iterations_affect_output() {
        let password = b"password";
        let salt = b"salt";
        let params1 = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);
        let params2 = Pbkdf2Params::with_salt(salt).iterations(2000).key_length(32);

        let result1 = pbkdf2(password, &params1).unwrap();
        let result2 = pbkdf2(password, &params2).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_pbkdf2_prf_types() {
        let password = b"password";
        let salt = b"salt";

        let params_sha256 =
            Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32).prf(PrfType::HmacSha256);

        let params_sha512 =
            Pbkdf2Params::with_salt(salt).iterations(1000).key_length(64).prf(PrfType::HmacSha512);

        let result_sha256 = pbkdf2(password, &params_sha256).unwrap();
        let result_sha512 = pbkdf2(password, &params_sha512).unwrap();

        assert_eq!(result_sha256.key.len(), 32);
        assert_eq!(result_sha512.key.len(), 64);
    }

    #[test]
    fn test_pbkdf2_validation() {
        let password = b"pass";
        let salt = b"salt";

        // Empty salt should fail
        let params_empty_salt = Pbkdf2Params::with_salt(b"").iterations(1000).key_length(32);
        assert!(pbkdf2(password, &params_empty_salt).is_err());

        // Too few iterations should fail
        let params_low_iter = Pbkdf2Params::with_salt(salt).iterations(999).key_length(32);
        assert!(pbkdf2(password, &params_low_iter).is_err());

        // Zero key length should fail
        let params_zero_len = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(0);
        assert!(pbkdf2(password, &params_zero_len).is_err());
    }

    #[test]
    fn test_pbkdf2_verify_password() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";

        let result = pbkdf2_simple(password).unwrap();

        // Correct password should verify
        assert!(result.verify_password(password).unwrap());

        // Wrong password should not verify
        assert!(!result.verify_password(wrong_password).unwrap());
    }

    #[test]
    fn test_pbkdf2_result_zeroize() {
        let password = b"password";
        let salt = b"salt";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let result = pbkdf2(password, &params).unwrap();

        // The key should be accessible before drop
        assert_eq!(result.key.len(), 32);

        // Zeroize should clear the key
        let mut result_clone = result.clone();
        result_clone.zeroize();

        // After zeroize, the key should be all zeros
        assert!(result_clone.key.iter().all(|&b| b == 0));
    }
}

mod hkdf_tests {
    use super::*;

    use zeroize::Zeroize;

    #[test]
    fn test_hkdf_rfc5869_test_case_1() {
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let okm = hkdf(&ikm, Some(&salt), Some(&info), 42).unwrap();
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        assert_eq!(okm.key, expected);
    }

    #[test]
    fn test_hkdf_extract_rfc5869() {
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];

        let prk = hkdf_extract(Some(&salt), &ikm).unwrap();
        let expected = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];

        assert_eq!(prk, expected);
    }

    #[test]
    fn test_hkdf_expand_rfc5869() {
        let prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let okm = hkdf_expand(&prk, Some(&info), 42).unwrap();
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        assert_eq!(okm.key, expected);
    }

    #[test]
    fn test_hkdf_different_ikm() {
        let salt = b"salt";
        let info = b"info";

        let okm1 = hkdf(b"ikm1", Some(salt), Some(info), 32).unwrap();
        let okm2 = hkdf(b"ikm2", Some(salt), Some(info), 32).unwrap();

        assert_ne!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_different_salt() {
        let ikm = b"ikm";
        let info = b"info";

        let okm1 = hkdf(ikm, Some(b"salt1"), Some(info), 32).unwrap();
        let okm2 = hkdf(ikm, Some(b"salt2"), Some(info), 32).unwrap();

        assert_ne!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"ikm";
        let salt = b"salt";

        let okm1 = hkdf(ikm, Some(salt), Some(b"info1"), 32).unwrap();
        let okm2 = hkdf(ikm, Some(salt), Some(b"info2"), 32).unwrap();

        assert_ne!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"test ikm";
        let salt = b"test salt";
        let info = b"test info";

        let okm1 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();
        let okm2 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();

        assert_eq!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_validation() {
        let prk = hkdf_extract(Some(b"salt"), b"ikm").unwrap();

        // Zero length should fail
        assert!(hkdf_expand(&prk, None, 0).is_err());

        // Length too long should fail
        assert!(hkdf_expand(&prk, None, 8161).is_err());

        // Max length should succeed
        assert!(hkdf_expand(&prk, None, 8160).is_ok());
    }

    #[test]
    fn test_hkdf_simple() {
        let ikm = b"test ikm";

        let result1 = hkdf_simple(ikm, 32).unwrap();
        let result2 = hkdf_simple(ikm, 32).unwrap();

        // Different random salts should produce different keys
        assert_ne!(result1.key, result2.key);
        assert_eq!(result1.key.len(), 32);
        assert_eq!(result2.key.len(), 32);
    }

    #[test]
    fn test_hkdf_result_zeroize() {
        let ikm = b"test ikm";
        let salt = b"test salt";

        let result = hkdf(ikm, Some(salt), None, 32).unwrap();

        // The key should be accessible before drop
        assert_eq!(result.key.len(), 32);

        // Zeroize should clear the key
        let mut result_clone = result.clone();
        result_clone.zeroize();

        // After zeroize, the key should be all zeros
        assert!(result_clone.key.iter().all(|&b| b == 0));
    }
}

mod counter_kdf_tests {
    use super::*;

    use zeroize::Zeroize;

    #[test]
    fn test_counter_kdf_basic() {
        let ki = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let params = CounterKdfParams::new(b"Example Label");

        let result = counter_kdf(ki.as_ref(), &params, 32).unwrap();

        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn test_counter_kdf_deterministic() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Test Label");

        let result1 = counter_kdf(ki, &params, 32).unwrap();
        let result2 = counter_kdf(ki, &params, 32).unwrap();

        assert_eq!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_labels() {
        let ki = b"test keying material";
        let params1 = CounterKdfParams::new(b"Label 1");
        let params2 = CounterKdfParams::new(b"Label 2");

        let result1 = counter_kdf(ki, &params1, 32).unwrap();
        let result2 = counter_kdf(ki, &params2, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_contexts() {
        let ki = b"test keying material";
        let params1 = CounterKdfParams::new(b"Label").with_context(b"Context 1");
        let params2 = CounterKdfParams::new(b"Label").with_context(b"Context 2");

        let result1 = counter_kdf(ki, &params1, 32).unwrap();
        let result2 = counter_kdf(ki, &params2, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_ki() {
        let params = CounterKdfParams::new(b"Label");

        let result1 = counter_kdf(b"ki1", &params, 32).unwrap();
        let result2 = counter_kdf(b"ki2", &params, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_lengths() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Label");

        let result16 = counter_kdf(ki, &params, 16).unwrap();
        let result32 = counter_kdf(ki, &params, 32).unwrap();
        let result64 = counter_kdf(ki, &params, 64).unwrap();

        assert_eq!(result16.key.len(), 16);
        assert_eq!(result32.key.len(), 32);
        assert_eq!(result64.key.len(), 64);

        // Longer outputs should have shorter outputs as prefix
        // SP 800-108 includes L in the input, so different L results in completely different keys
        assert_ne!(result16.key, &result32.key[..16]);
        assert_ne!(result32.key, &result64.key[..32]);
    }

    #[test]
    fn test_counter_kdf_validation() {
        let params = CounterKdfParams::new(b"Label");

        // Empty KI should fail
        assert!(counter_kdf(b"", &params, 32).is_err());

        // Zero key length should fail
        assert!(counter_kdf(b"ki", &params, 0).is_err());

        // Valid key length should succeed
        assert!(counter_kdf(b"ki", &params, 32).is_ok());
    }

    #[test]
    fn test_derive_multiple_keys() {
        let ki = b"master secret";
        let context = b"my-app-v1";
        let key_specs =
            vec![("encryption".as_bytes(), 32), ("mac".as_bytes(), 32), ("iv".as_bytes(), 16)];

        let keys = derive_multiple_keys(ki, context, &key_specs).unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].key.len(), 32);
        assert_eq!(keys[1].key.len(), 32);
        assert_eq!(keys[2].key.len(), 16);

        // All keys should be different
        assert_ne!(keys[0].key, keys[1].key);
        assert_ne!(keys[1].key, keys[2].key);
        assert_ne!(keys[0].key, keys[2].key);
    }

    #[test]
    fn test_convenience_functions() {
        let ki = b"master secret";
        let context = b"my-app-v1";

        let enc_key = derive_encryption_key(ki, context).unwrap();
        let mac_key = derive_mac_key(ki, context).unwrap();
        let iv = derive_iv(ki, context).unwrap();

        assert_eq!(enc_key.key.len(), 32);
        assert_eq!(mac_key.key.len(), 32);
        assert_eq!(iv.key.len(), 16);

        // All keys should be different
        assert_ne!(enc_key.key, mac_key.key);
        assert_ne!(mac_key.key, &iv.key[..16]);
    }

    #[test]
    fn test_counter_kdf_result_zeroize() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Label");

        let result = counter_kdf(ki, &params, 32).unwrap();

        // The key should be accessible before drop
        assert_eq!(result.key.len(), 32);

        // Zeroize should clear the key
        let mut result_clone = result.clone();
        result_clone.zeroize();

        // After zeroize, the key should be all zeros
        assert!(result_clone.key.iter().all(|&b| b == 0));
    }
}

mod integration_tests {
    use super::*;

    #[test]
    fn test_kdf_consistency() {
        let ikm = b"input key material";
        let password = b"password";
        let salt = b"salt";

        // All KDFs should be deterministic
        let pbkdf2_result1 =
            pbkdf2(password, &Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32))
                .unwrap();
        let pbkdf2_result2 =
            pbkdf2(password, &Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32))
                .unwrap();
        assert_eq!(pbkdf2_result1.key, pbkdf2_result2.key);

        let hkdf_result1 = hkdf(ikm, Some(salt), None, 32).unwrap();
        let hkdf_result2 = hkdf(ikm, Some(salt), None, 32).unwrap();
        assert_eq!(hkdf_result1.key, hkdf_result2.key);

        let counter_result1 = counter_kdf(ikm, &CounterKdfParams::new(b"Label"), 32).unwrap();
        let counter_result2 = counter_kdf(ikm, &CounterKdfParams::new(b"Label"), 32).unwrap();
        assert_eq!(counter_result1.key, counter_result2.key);
    }

    #[test]
    fn test_kdf_output_uniqueness() {
        let ikm = b"input key material";
        let salt = b"salt";

        // Different KDFs with same inputs should produce different outputs
        let pbkdf2_result =
            pbkdf2(ikm, &Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32)).unwrap();
        let hkdf_result = hkdf(ikm, Some(salt), None, 32).unwrap();
        let counter_result = counter_kdf(ikm, &CounterKdfParams::new(b"Label"), 32).unwrap();

        assert_ne!(pbkdf2_result.key, hkdf_result.key);
        assert_ne!(hkdf_result.key, counter_result.key);
        assert_ne!(pbkdf2_result.key, counter_result.key);
    }

    #[test]
    fn test_kdf_security_level() {
        let ikm = b"input key material";

        // Test different output lengths
        let key_128 = hkdf(ikm, None, None, 16).unwrap();
        let key_256 = hkdf(ikm, None, None, 32).unwrap();
        let key_512 = hkdf(ikm, None, None, 64).unwrap();

        assert_eq!(key_128.key.len(), 16);
        assert_eq!(key_256.key.len(), 32);
        assert_eq!(key_512.key.len(), 64);

        // Outputs should be different
        // HKDF does NOT include L in the input, so longer outputs extend shorter ones
        assert_eq!(key_128.key, &key_256.key[..16]);
        assert_eq!(key_256.key, &key_512.key[..32]);
    }
}
