#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # BLS12-381 Pairing Curve Operations
//!
//! BLS12-381 pairing operations using ark-bls12-381 crate.
//! Provides pairing-based cryptography for Zcash, Ethereum 2.0, and other protocols.

use super::traits::EcPairing;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{BigInteger, One};

/// BLS12-381 pairing implementation
pub struct Bls12_381Pairing;

impl EcPairing for Bls12_381Pairing {
    type G1 = G1Affine;
    type G2 = G2Affine;
    type GT = PairingOutput<Bls12_381>;

    fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT {
        Bls12_381::pairing(g1, g2)
    }

    fn is_identity(gt: &Self::GT) -> bool {
        gt.0.is_one()
    }

    fn g1_generator() -> Self::G1 {
        G1Affine::generator()
    }

    fn g2_generator() -> Self::G2 {
        G2Affine::generator()
    }

    fn g1_mul(generator: &Self::G1, scalar: &[u8]) -> Self::G1 {
        let scalar_fr = scalar_to_fr(scalar);
        (*generator * scalar_fr).into_affine()
    }

    fn g2_mul(generator: &Self::G2, scalar: &[u8]) -> Self::G2 {
        let scalar_fr = scalar_to_fr(scalar);
        (*generator * scalar_fr).into_affine()
    }
}

/// Convert byte slice to Fr scalar
fn scalar_to_fr(scalar: &[u8]) -> Fr {
    // Take first 32 bytes, pad or truncate as needed
    let mut bytes = [0u8; 32];
    let len = std::cmp::min(scalar.len(), 32);
    bytes[..len].copy_from_slice(&scalar[..len]);

    // Convert bytes to bits (big-endian)
    let mut bits = [false; 256];
    for (i, &byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            bits[i * 8 + j] = (byte >> (7 - j)) & 1 == 1;
        }
    }

    // Convert to BigInteger and then to Fr
    let bigint = ark_ff::BigInteger256::from_bits_be(&bits);
    Fr::from(bigint)
}

/// BLS12-381 G1 group operations
pub struct Bls12_381G1;

impl Bls12_381G1 {
    /// Get the generator point
    pub fn generator() -> G1Affine {
        G1Affine::generator()
    }

    /// Check if point is on curve
    pub fn is_on_curve(point: &G1Affine) -> bool {
        point.is_on_curve()
    }

    /// Check if point is in subgroup
    pub fn is_in_subgroup(point: &G1Affine) -> bool {
        point.is_in_correct_subgroup_assuming_on_curve()
    }

    /// Scalar multiplication
    pub fn mul(point: &G1Affine, scalar: &[u8]) -> G1Affine {
        let scalar_fr = scalar_to_fr(scalar);
        (*point * scalar_fr).into_affine()
    }

    /// Point addition
    pub fn add(a: &G1Affine, b: &G1Affine) -> G1Affine {
        (*a + *b).into_affine()
    }
}

/// BLS12-381 G2 group operations
pub struct Bls12_381G2;

impl Bls12_381G2 {
    /// Get the generator point
    pub fn generator() -> G2Affine {
        G2Affine::generator()
    }

    /// Check if point is on curve
    pub fn is_on_curve(point: &G2Affine) -> bool {
        point.is_on_curve()
    }

    /// Check if point is in subgroup
    pub fn is_in_subgroup(point: &G2Affine) -> bool {
        point.is_in_correct_subgroup_assuming_on_curve()
    }

    /// Scalar multiplication
    pub fn mul(point: &G2Affine, scalar: &[u8]) -> G2Affine {
        let scalar_fr = scalar_to_fr(scalar);
        (*point * scalar_fr).into_affine()
    }

    /// Point addition
    pub fn add(a: &G2Affine, b: &G2Affine) -> G2Affine {
        (*a + *b).into_affine()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quantumshield_prelude::error::Result;

    #[test]
    fn test_bls12_381_pairing_bilinearity() -> Result<()> {
        let g1 = Bls12_381Pairing::g1_generator();
        let g2 = Bls12_381Pairing::g2_generator();

        let scalar1 = [1u8; 32];
        let scalar2 = [2u8; 32];

        let g1_s1 = Bls12_381Pairing::g1_mul(&g1, &scalar1);
        let g2_s2 = Bls12_381Pairing::g2_mul(&g2, &scalar2);

        let pairing1 = Bls12_381Pairing::pairing(&g1_s1, &g2_s2);

        let g1_s2 = Bls12_381Pairing::g1_mul(&g1, &scalar2);
        let g2_s1 = Bls12_381Pairing::g2_mul(&g2, &scalar1);

        let pairing2 = Bls12_381Pairing::pairing(&g1_s2, &g2_s1);

        // Bilinearity: e(g1^a, g2^b) = e(g1^b, g2^a)
        assert_eq!(pairing1, pairing2);

        Ok(())
    }

    #[test]
    fn test_bls12_381_pairing_identity() -> Result<()> {
        let g1 = Bls12_381Pairing::g1_generator();
        let g2 = Bls12_381Pairing::g2_generator();

        let identity = Bls12_381Pairing::pairing(&G1Affine::identity(), &g2);
        assert!(Bls12_381Pairing::is_identity(&identity));

        let identity2 = Bls12_381Pairing::pairing(&g1, &G2Affine::identity());
        assert!(Bls12_381Pairing::is_identity(&identity2));

        Ok(())
    }

    #[test]
    fn test_bls12_381_g1_operations() -> Result<()> {
        let r#gen = Bls12_381G1::generator();
        assert!(Bls12_381G1::is_on_curve(&r#gen));
        assert!(Bls12_381G1::is_in_subgroup(&r#gen));

        let scalar = [42u8; 32];
        let result = Bls12_381G1::mul(&r#gen, &scalar);
        assert!(Bls12_381G1::is_on_curve(&result));
        assert!(Bls12_381G1::is_in_subgroup(&result));

        Ok(())
    }

    #[test]
    fn test_bls12_381_g2_operations() -> Result<()> {
        let r#gen = Bls12_381G2::generator();
        assert!(Bls12_381G2::is_on_curve(&r#gen));
        assert!(Bls12_381G2::is_in_subgroup(&r#gen));

        let scalar = [42u8; 32];
        let result = Bls12_381G2::mul(&r#gen, &scalar);
        assert!(Bls12_381G2::is_on_curve(&result));
        assert!(Bls12_381G2::is_in_subgroup(&result));

        Ok(())
    }
}
