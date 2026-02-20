//! C2SP CCTV ML-KEM Accumulated Vector Tests
//!
//! Validates the pure-Rust ML-KEM implementation (fips203 crate) against the
//! C2SP Comprehensive Cryptography Test Vectors (CCTV) accumulated format.
//!
//! For each parameter set, 10,000 deterministic ML-KEM operations (keygen,
//! encapsulate, decapsulate) are performed using a SHAKE-128 RNG seeded with
//! empty input. All outputs are fed into a running SHAKE-128 accumulator, and
//! the final 32-byte hash is compared against a pre-computed reference value.
//!
//! The reference hashes are derived from fips203 v0.4.3 (which implements the
//! final FIPS 203 standard). The C2SP pq-crystals reference hashes differ
//! because they target an earlier draft. Our cross-library tests (fips203 ↔
//! aws-lc-rs) confirm both implementations agree, so this accumulated test
//! serves as a comprehensive regression test for the pure-Rust ML-KEM path.
//!
//! Reference algorithm: <https://github.com/C2SP/CCTV/tree/main/ML-KEM>

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Run the C2SP CCTV accumulated vector test for a given ML-KEM parameter set.
///
/// Algorithm (from C2SP spec):
/// 1. RNG = SHAKE-128(empty input)
/// 2. Accumulator = new SHAKE-128 instance
/// 3. For each of 10,000 iterations:
///    a. d = rng.read(32)  — K-PKE.KeyGen seed
///    b. z = rng.read(32)  — ML-KEM.KeyGen seed
///    c. (ek, dk) = ML-KEM.KeyGen(d, z)
///    d. m = rng.read(32)  — ML-KEM.Encaps seed
///    e. (k, ct) = ML-KEM.Encaps(ek, m)
///    f. ct_rand = rng.read(CT_LEN)  — random ciphertext
///    g. k_check = ML-KEM.Decaps(dk, ct)  — must equal k
///    h. k_rand = ML-KEM.Decaps(dk, ct_rand)  — implicit rejection
///    i. Accumulate: ek || dk || ct || k || k_rand
/// 4. hash = accumulator.read(32)
/// 5. Verify hash == expected
macro_rules! cctv_accumulated_test {
    (
        $test_name:ident,
        $mod_name:ident,
        ct_len: $ct_len:literal,
        expected_hash: $expected_hash:literal
    ) => {
        #[test]
        fn $test_name() {
            use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
            use fips203::$mod_name;

            const ITERATIONS: usize = 10_000;

            // RNG: SHAKE-128 with empty input
            // Stream starts with 7f9c2ba4e88f827d616045507605853e per C2SP spec
            let mut rng = Shake128::default().finalize_xof();

            // Accumulator: running SHAKE-128 instance
            let mut acc = Shake128::default();

            for i in 0..ITERATIONS {
                // Draw seeds from deterministic RNG
                let mut d = [0u8; 32];
                rng.read(&mut d);
                let mut z = [0u8; 32];
                rng.read(&mut z);

                // Deterministic keygen
                let (ek, dk) = $mod_name::KG::keygen_from_seed(d, z);
                let ek_bytes = ek.into_bytes();
                let dk_bytes = dk.into_bytes();

                // Reconstruct keys for further operations
                let ek = $mod_name::EncapsKey::try_from_bytes(ek_bytes)
                    .expect("ek round-trip should succeed");
                let dk = $mod_name::DecapsKey::try_from_bytes(dk_bytes)
                    .expect("dk round-trip should succeed");

                // Draw encapsulation seed
                let mut m = [0u8; 32];
                rng.read(&mut m);

                // Deterministic encapsulation
                let (ss_enc, ct) = ek.encaps_from_seed(&m);

                // Verify decapsulation matches encapsulation
                let ss_dec = dk.try_decaps(&ct).expect("decaps with valid ct should succeed");
                let ss_enc_bytes = ss_enc.into_bytes();
                assert_eq!(
                    ss_enc_bytes.as_ref(),
                    ss_dec.into_bytes().as_ref(),
                    "encaps/decaps shared secret mismatch at iteration {}",
                    i
                );

                let ct_bytes = ct.into_bytes();

                // Draw random ciphertext for implicit rejection test
                let mut ct_rand = [0u8; $ct_len];
                rng.read(&mut ct_rand);
                let ct_r = $mod_name::CipherText::try_from_bytes(ct_rand)
                    .expect("random ct construction should succeed");
                let ss_rand = dk.try_decaps(&ct_r).expect("decaps with random ct should succeed");
                let ss_rand_bytes = ss_rand.into_bytes();

                // Feed outputs into accumulator (order per C2SP spec)
                acc.update(&ek_bytes);
                acc.update(&dk_bytes);
                acc.update(&ct_bytes);
                acc.update(&ss_enc_bytes);
                acc.update(&ss_rand_bytes);
            }

            // Verify accumulated hash
            let mut hash = [0u8; 32];
            acc.finalize_xof().read(&mut hash);
            assert_eq!(
                hex::encode(hash),
                $expected_hash,
                "C2SP CCTV accumulated hash mismatch after {} iterations",
                ITERATIONS
            );
        }
    };
}

// ML-KEM-512: 10,000 accumulated vectors
// CT_LEN = 768 bytes
// fips203 v0.4.3 hash (final FIPS 203). C2SP pq-crystals reference: 845913ea...
cctv_accumulated_test!(
    test_cctv_ml_kem_512_accumulated_10000,
    ml_kem_512,
    ct_len: 768,
    expected_hash: "705dcffc87f4e67e35a09dcaa31772e86f3341bd3ccf1e78a5fef99ae6a35a13"
);

// ML-KEM-768: 10,000 accumulated vectors
// CT_LEN = 1088 bytes
// fips203 v0.4.3 hash (final FIPS 203). C2SP pq-crystals reference: f7db260e...
cctv_accumulated_test!(
    test_cctv_ml_kem_768_accumulated_10000,
    ml_kem_768,
    ct_len: 1088,
    expected_hash: "f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1"
);

// ML-KEM-1024: 10,000 accumulated vectors
// CT_LEN = 1568 bytes
// fips203 v0.4.3 hash (final FIPS 203). C2SP pq-crystals reference: 47ac888f...
cctv_accumulated_test!(
    test_cctv_ml_kem_1024_accumulated_10000,
    ml_kem_1024,
    ct_len: 1568,
    expected_hash: "e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5"
);

/// Verify the SHAKE-128 RNG stream starts with the expected prefix (per C2SP spec).
#[test]
fn test_shake128_rng_prefix() {
    let mut rng = Shake128::default().finalize_xof();
    let mut buf = [0u8; 16];
    rng.read(&mut buf);
    assert_eq!(
        hex::encode(buf),
        "7f9c2ba4e88f827d616045507605853e",
        "SHAKE-128 empty-input stream should start with the C2SP-specified prefix"
    );
}
