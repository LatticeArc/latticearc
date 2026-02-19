#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # BN254 Pairing Curve Operations
//!
//! BN254 (alt_bn128) pairing operations using ark-bn254 crate.
//! Provides Ethereum-compatible pairing operations for ZK proofs and smart contracts.

use super::traits::EcPairing;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{BigInteger, One};

/// BN254 pairing implementation
pub struct Bn254Pairing;

impl EcPairing for Bn254Pairing {
    type G1 = G1Affine;
    type G2 = G2Affine;
    type GT = PairingOutput<Bn254>;

    fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT {
        Bn254::pairing(g1, g2)
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

/// BN254 G1 group operations
pub struct Bn254G1;

impl Bn254G1 {
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

/// BN254 G2 group operations
pub struct Bn254G2;

impl Bn254G2 {
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
    fn test_bn254_pairing_bilinearity() -> Result<()> {
        let g1 = Bn254Pairing::g1_generator();
        let g2 = Bn254Pairing::g2_generator();

        let scalar1 = [1u8; 32];
        let scalar2 = [2u8; 32];

        let g1_s1 = Bn254Pairing::g1_mul(&g1, &scalar1);
        let g2_s2 = Bn254Pairing::g2_mul(&g2, &scalar2);

        let pairing1 = Bn254Pairing::pairing(&g1_s1, &g2_s2);

        let g1_s2 = Bn254Pairing::g1_mul(&g1, &scalar2);
        let g2_s1 = Bn254Pairing::g2_mul(&g2, &scalar1);

        let pairing2 = Bn254Pairing::pairing(&g1_s2, &g2_s1);

        // Bilinearity: e(g1^a, g2^b) = e(g1^b, g2^a)
        assert_eq!(pairing1, pairing2);

        Ok(())
    }

    #[test]
    fn test_bn254_pairing_identity() -> Result<()> {
        let g1 = Bn254Pairing::g1_generator();
        let g2 = Bn254Pairing::g2_generator();

        let identity = Bn254Pairing::pairing(&G1Affine::identity(), &g2);
        assert!(Bn254Pairing::is_identity(&identity));

        let identity2 = Bn254Pairing::pairing(&g1, &G2Affine::identity());
        assert!(Bn254Pairing::is_identity(&identity2));

        Ok(())
    }

    #[test]
    fn test_bn254_g1_operations() -> Result<()> {
        let r#gen = Bn254G1::generator();
        assert!(Bn254G1::is_on_curve(&r#gen));
        assert!(Bn254G1::is_in_subgroup(&r#gen));

        let scalar = [42u8; 32];
        let result = Bn254G1::mul(&r#gen, &scalar);
        assert!(Bn254G1::is_on_curve(&result));
        assert!(Bn254G1::is_in_subgroup(&result));

        Ok(())
    }

    #[test]
    fn test_bn254_g2_operations() -> Result<()> {
        let r#gen = Bn254G2::generator();
        assert!(Bn254G2::is_on_curve(&r#gen));
        assert!(Bn254G2::is_in_subgroup(&r#gen));

        let scalar = [42u8; 32];
        let result = Bn254G2::mul(&r#gen, &scalar);
        assert!(Bn254G2::is_on_curve(&result));
        assert!(Bn254G2::is_in_subgroup(&result));

        Ok(())
    }
}
