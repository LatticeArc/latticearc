#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Hash-to-curve for NIST P-256 (RFC 9380)
//!
//! [`p256_xmd_sha256_sswu_ro`] implements the RFC 9380 suite
//! `P256_XMD:SHA-256_SSWU_RO_` (§8.2): `expand_message_xmd` with SHA-256,
//! `hash_to_field` producing two field elements, the simplified SWU map, and
//! point addition (the random-oracle construction; P-256 has cofactor 1).
//! The output is the 65-byte uncompressed SEC1 encoding of the point.
//!
//! aws-lc-rs exposes no hash-to-curve API, so this module uses the RustCrypto
//! `p256` crate (`hash2curve` feature, pure Rust, `#![forbid(unsafe_code)]`).
//! Correctness is pinned by the five RFC 9380 Appendix J.1.1 vectors in the
//! tests below. The `p256` crate's arithmetic has not been independently
//! audited (its README says so); it aims to be constant time but that is
//! unverified, so treat hashing *secret* inputs to the curve accordingly.
//!
//! ## Secret messages and timing
//!
//! This function makes **no constant-time guarantee**. This module adds no
//! branch on message bytes: its early returns depend only on `dst.len()` and
//! `msg.len()`, which are treated as public, and on the identity-point case.
//! The secret-dependent work is in the `hash2curve` 0.14.0 /
//! `primeorder` 0.14.0 / `p256` 0.14.0 code: SHA-256 `expand_message_xmd`,
//! the 48-byte field reduction, the simplified SWU map and the affine
//! conversion. A source reading of those versions finds `subtle`
//! conditional selects in the SWU map, a fixed addition chain for the square
//! root, the non-`vartime` field inversion, and `vartime` helpers used only
//! with public exponents; it does not establish that the compiled code or
//! the CPU's multiply instructions are data-independent.
//!
//! The timing evidence is bounded and empirical. The
//! `bench_h2c_p256_secret_msg` bench in `tests/examples/dudect_ct.rs`
//! (Welch's t-test, fixed vs random 32-byte message, 100 000 samples) is
//! gated at `|t| > 10` by `.github/workflows/dudect.yml` on x86_64 and
//! aarch64 Linux runners. On an Apple M4 (aarch64 macOS, rustc 1.99.1, 2026-10)
//! six runs gave `|t|` at most 2.8, while a deliberate early-exit compare
//! of a few nanoseconds reached `|t|` of 20 or more on the same setup.
//! That covers wall-clock timing on the measured CPUs with these dependency
//! versions and toolchain only. It is not a proof, says nothing about cache
//! or other microarchitectural channels, and must be repeated after a
//! `p256`, compiler or target change. The Valgrind (`ctgrind`) harness does
//! not cover this path.
//!
//! ## Inputs
//!
//! - `dst`, the domain separation tag, must be 1 to 255 bytes (RFC 9380
//!   §3.1). Longer tags are refused rather than hashed down with the
//!   `H2C-OVERSIZE-DST-` rule; callers with such a tag can apply that rule
//!   themselves.
//! - `msg` is bounded by the signature-message resource limit
//!   (`max_signature_size_bytes`, 64 KiB by default).
//!
//! ## FIPS
//!
//! Hash-to-curve is not a FIPS-approved algorithm and the `p256` crate is
//! outside the aws-lc-rs module boundary; see
//! `docs/FIPS_SECURITY_POLICY.md`.

use p256::NistP256;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::hash2curve::{ExpandMsgXmd, hash_from_bytes};
use sha2::Sha256;

use crate::prelude::error::{LatticeArcError, Result};
use crate::primitives::resource_limits::validate_signature_size;

/// Length of the uncompressed SEC1 point returned by
/// [`p256_xmd_sha256_sswu_ro`].
pub const P256_H2C_OUTPUT_LEN: usize = 65;

/// Largest domain separation tag accepted (RFC 9380 §3.1).
pub const H2C_MAX_DST_LEN: usize = 255;

/// Hash `msg` to a point on NIST P-256 with the RFC 9380 suite
/// `P256_XMD:SHA-256_SSWU_RO_` and return it as 65-byte uncompressed SEC1
/// (`0x04 || X || Y`).
///
/// # Errors
///
/// Returns `InvalidInput` if `dst` is empty or longer than
/// [`H2C_MAX_DST_LEN`] bytes, and `MessageTooLong` if `msg` exceeds the
/// signature-message resource limit. Returns `InvalidData` in the
/// probability-2^-256 case that the result is the point at infinity, which
/// has no uncompressed encoding.
#[must_use = "the hashed point must be used"]
pub fn p256_xmd_sha256_sswu_ro(msg: &[u8], dst: &[u8]) -> Result<[u8; P256_H2C_OUTPUT_LEN]> {
    if dst.is_empty() || dst.len() > H2C_MAX_DST_LEN {
        tracing::debug!(dst_len = dst.len(), "hash-to-curve rejected: DST length");
        return Err(LatticeArcError::InvalidInput(
            "hash-to-curve DST must be 1 to 255 bytes".to_string(),
        ));
    }
    if let Err(e) = validate_signature_size(msg.len()) {
        tracing::debug!(error = %e, msg_len = msg.len(), "hash-to-curve rejected: message exceeds resource limit");
        return Err(LatticeArcError::MessageTooLong);
    }

    let point = hash_from_bytes::<NistP256, ExpandMsgXmd<Sha256>>(&[msg], &[dst]).map_err(|e| {
        tracing::debug!(error = %e, "hash-to-curve expand_message_xmd failed");
        LatticeArcError::InvalidInput("hash-to-curve input rejected".to_string())
    })?;

    let encoded = point.to_sec1_point(false);
    <[u8; P256_H2C_OUTPUT_LEN]>::try_from(encoded.as_bytes()).map_err(|_e| {
        tracing::debug!("hash-to-curve produced the identity point");
        LatticeArcError::InvalidData("hash-to-curve produced the identity point".to_string())
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test-only length arithmetic on small constants")]
#[expect(clippy::unwrap_used, reason = "tests use unwrap on statically valid inputs")]
#[expect(clippy::indexing_slicing, reason = "tests index into fixed-size outputs")]
mod tests {
    use super::*;

    /// DST of the RFC 9380 Appendix J.1.1 vectors.
    const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

    enum Msg {
        Literal(&'static [u8]),
        /// `prefix` followed by `count` copies of `byte` (the q128 / a512
        /// inputs).
        Repeat(&'static [u8], u8, usize),
    }

    impl Msg {
        fn bytes(&self) -> Vec<u8> {
            match self {
                Msg::Literal(b) => b.to_vec(),
                Msg::Repeat(prefix, byte, count) => {
                    let mut v = prefix.to_vec();
                    v.resize(prefix.len() + count, *byte);
                    v
                }
            }
        }
    }

    struct Vector {
        msg: Msg,
        x: &'static str,
        y: &'static str,
    }

    /// RFC 9380 Appendix J.1.1 (`P256_XMD:SHA-256_SSWU_RO_`), the `P.x` and
    /// `P.y` values for each of the five messages, copied from
    /// <https://www.rfc-editor.org/rfc/rfc9380.txt>.
    const RFC9380_J_1_1: &[Vector] = &[
        Vector {
            msg: Msg::Literal(b""),
            x: "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            y: "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        },
        Vector {
            msg: Msg::Literal(b"abc"),
            x: "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            y: "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        },
        Vector {
            msg: Msg::Literal(b"abcdef0123456789"),
            x: "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
            y: "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
        },
        Vector {
            msg: Msg::Repeat(b"q128_", b'q', 128),
            x: "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
            y: "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
        },
        Vector {
            msg: Msg::Repeat(b"a512_", b'a', 512),
            x: "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
            y: "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
        },
    ];

    #[test]
    fn rfc9380_appendix_j_1_1_vectors() {
        let lens: Vec<usize> = RFC9380_J_1_1.iter().map(|v| v.msg.bytes().len()).collect();
        assert_eq!(lens, vec![0, 3, 16, 133, 517]);
        for v in RFC9380_J_1_1 {
            let msg = v.msg.bytes();
            let point = p256_xmd_sha256_sswu_ro(&msg, DST).unwrap();
            assert_eq!(point[0], 0x04);
            assert_eq!(hex::encode(&point[1..33]), v.x, "P.x for msg of {} bytes", msg.len());
            assert_eq!(hex::encode(&point[33..]), v.y, "P.y for msg of {} bytes", msg.len());
        }
    }

    #[test]
    fn output_is_a_valid_p256_public_point() {
        let point = p256_xmd_sha256_sswu_ro(b"abc", DST).unwrap();
        assert!(p256::PublicKey::from_sec1_bytes(&point).is_ok());
    }

    #[test]
    fn dst_and_message_separate_outputs() {
        let a = p256_xmd_sha256_sswu_ro(b"abc", DST).unwrap();
        let b = p256_xmd_sha256_sswu_ro(b"abd", DST).unwrap();
        let c = p256_xmd_sha256_sswu_ro(b"abc", b"another-dst").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn dst_length_bounds() {
        assert!(matches!(
            p256_xmd_sha256_sswu_ro(b"m", b""),
            Err(LatticeArcError::InvalidInput(_))
        ));
        assert!(p256_xmd_sha256_sswu_ro(b"m", &[0x41; H2C_MAX_DST_LEN]).is_ok());
        assert!(matches!(
            p256_xmd_sha256_sswu_ro(b"m", &[0x41; H2C_MAX_DST_LEN + 1]),
            Err(LatticeArcError::InvalidInput(_))
        ));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let limit = crate::primitives::resource_limits::get_global_resource_limits()
            .get_limits()
            .unwrap()
            .max_signature_size_bytes;
        let big = vec![0u8; limit + 1];
        assert!(matches!(p256_xmd_sha256_sswu_ro(&big, DST), Err(LatticeArcError::MessageTooLong)));
        assert!(p256_xmd_sha256_sswu_ro(&big[..limit], DST).is_ok());
    }
}
