//! Hybrid ML-DSA + Ed25519 signatures and single-algorithm ML-DSA, with
//! required contexts, pre-hashed modes and seed-based key generation.

use std::sync::Arc;

use latticearc::hybrid::sig_hybrid::HybridSignatureError;
use latticearc::hybrid::sig_hybrid::{
    HybridSigPublicKey as CoreSigPublicKey, HybridSigSecretKey as CoreSigSecretKey,
    HybridSignature, generate_keypair_from_seed, generate_keypair_with_parameter_set,
    sign_prehashed as core_sign_prehashed, sign_with_context,
    verify_prehashed as core_verify_prehashed, verify_with_context,
};
use latticearc::hybrid::wire::WireEncode;
use latticearc::primitives::sig::ml_dsa::MlDsaError;
use latticearc::primitives::sig::ml_dsa::{
    MlDsaParameterSet as CoreSet, MlDsaPublicKey as CoreMlDsaPublicKey,
    MlDsaSecretKey as CoreMlDsaSecretKey, MlDsaSignature, PrehashAlgorithm as CorePrehash,
    generate_keypair as ml_dsa_generate, generate_keypair_from_seed as ml_dsa_generate_from_seed,
};
use zeroize::Zeroizing;

use crate::error::LatticeArcError;
use crate::secrets::{SecretBytes, take_zeroizing};

/// ML-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (NIST category 2).
    MlDsa44,
    /// ML-DSA-65 (NIST category 3), the default.
    MlDsa65,
    /// ML-DSA-87 (NIST category 5).
    MlDsa87,
}

impl From<MlDsaParameterSet> for CoreSet {
    fn from(s: MlDsaParameterSet) -> Self {
        match s {
            MlDsaParameterSet::MlDsa44 => Self::MlDsa44,
            MlDsaParameterSet::MlDsa65 => Self::MlDsa65,
            MlDsaParameterSet::MlDsa87 => Self::MlDsa87,
        }
    }
}

impl TryFrom<CoreSet> for MlDsaParameterSet {
    type Error = LatticeArcError;

    fn try_from(s: CoreSet) -> Result<Self, Self::Error> {
        match s {
            CoreSet::MlDsa44 => Ok(Self::MlDsa44),
            CoreSet::MlDsa65 => Ok(Self::MlDsa65),
            CoreSet::MlDsa87 => Ok(Self::MlDsa87),
            _ => Err(LatticeArcError::internal(format!("unsupported ML-DSA parameter set {s:?}"))),
        }
    }
}

/// Hash function a caller used to pre-hash content for HashML-DSA
/// (FIPS 204 Algorithm 4). SHA-512 and SHAKE256 are allowed at every
/// parameter set; SHA-256 and SHAKE128 only at ML-DSA-44.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PrehashAlgorithm {
    /// SHA-256, 32-byte digest.
    Sha256,
    /// SHA-512, 64-byte digest.
    Sha512,
    /// SHAKE128 with 256-bit output.
    Shake128,
    /// SHAKE256 with 512-bit output.
    Shake256,
}

/// The core crate reports a signature that does not verify as an error;
/// the FFI reports it as `Ok(false)` so callers branch on a boolean and
/// errors are left for malformed input.
fn hybrid_verdict(r: Result<bool, HybridSignatureError>) -> Result<bool, LatticeArcError> {
    match r {
        Ok(valid) => Ok(valid),
        Err(HybridSignatureError::VerificationFailed(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Same rule as [`hybrid_verdict`] for single-algorithm ML-DSA.
fn ml_dsa_verdict(r: Result<bool, MlDsaError>) -> Result<bool, LatticeArcError> {
    match r {
        Ok(valid) => Ok(valid),
        Err(MlDsaError::VerificationError(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// FIPS 204 §3.3 context limit for plain ML-DSA.
const ML_DSA_MAX_CONTEXT_LEN: usize = 255;

/// The core reports a context over 255 bytes through its opaque sign /
/// verify errors; checked here so the caller sees `InvalidContext`.
fn check_ml_dsa_context(context: &[u8]) -> Result<(), LatticeArcError> {
    if context.len() > ML_DSA_MAX_CONTEXT_LEN {
        return Err(LatticeArcError::InvalidContext {
            reason: format!(
                "ML-DSA context must be at most {ML_DSA_MAX_CONTEXT_LEN} bytes, got {}",
                context.len()
            ),
        });
    }
    Ok(())
}

/// HashML-DSA inputs the core rejects opaquely, checked here so a
/// misconfiguration is a typed error rather than a signature that never
/// verifies: a non-empty context of at most 255 bytes, a hash permitted at
/// the parameter set (FIPS 204 §5.4) and a digest of that hash's length.
fn check_prehash(
    set: CoreSet,
    hash: CorePrehash,
    digest: &[u8],
    context: &[u8],
) -> Result<(), LatticeArcError> {
    if context.is_empty() {
        return Err(LatticeArcError::InvalidContext {
            reason: "HashML-DSA context must not be empty".to_string(),
        });
    }
    check_ml_dsa_context(context)?;
    if !hash.is_permitted_for(set) {
        return Err(LatticeArcError::InvalidParams {
            reason: format!("{} is below the FIPS 204 strength floor for {set:?}", hash.name()),
        });
    }
    if digest.len() != hash.digest_len() {
        return Err(LatticeArcError::invalid_input(format!(
            "{} digest must be {} bytes, got {}",
            hash.name(),
            hash.digest_len(),
            digest.len()
        )));
    }
    Ok(())
}

impl From<PrehashAlgorithm> for CorePrehash {
    fn from(h: PrehashAlgorithm) -> Self {
        match h {
            PrehashAlgorithm::Sha256 => Self::Sha256,
            PrehashAlgorithm::Sha512 => Self::Sha512,
            PrehashAlgorithm::Shake128 => Self::Shake128,
            PrehashAlgorithm::Shake256 => Self::Shake256,
        }
    }
}

// ---------------------------------------------------------------------------
// Hybrid ML-DSA + Ed25519
// ---------------------------------------------------------------------------

/// A hybrid signature public key (ML-DSA + Ed25519).
#[derive(uniffi::Object)]
pub struct HybridSigPublicKey {
    inner: CoreSigPublicKey,
    set: MlDsaParameterSet,
}

impl HybridSigPublicKey {
    fn wrap(inner: CoreSigPublicKey) -> Result<Arc<Self>, LatticeArcError> {
        let set = inner.parameter_set().try_into()?;
        Ok(Arc::new(Self { inner, set }))
    }
}

#[uniffi::export]
impl HybridSigPublicKey {
    /// Parses the LatticeArc wire encoding produced by `to_wire`.
    ///
    /// # Errors
    ///
    /// `WireFormat` for anything that is not a well-formed public key.
    #[uniffi::constructor]
    pub fn from_wire(bytes: Vec<u8>) -> Result<Arc<Self>, LatticeArcError> {
        Self::wrap(CoreSigPublicKey::from_wire(&bytes)?)
    }

    /// The versioned wire encoding.
    ///
    /// # Errors
    ///
    /// `WireFormat` if the key's components have inconsistent lengths.
    pub fn to_wire(&self) -> Result<Vec<u8>, LatticeArcError> {
        Ok(self.inner.to_wire()?)
    }

    /// The ML-DSA parameter set.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.set
    }
}

/// The components of a hybrid signing key, returned only by
/// [`HybridSigningKey::export_parts`].
///
/// This is an explicit export: the fields are plain byte strings the caller
/// now owns and must clear after persisting them. The record is not
/// comparable, cloneable or printable. `from_parts` checks lengths only; a
/// public half that does not belong to the secret half produces signatures
/// that never verify, so store the parts together.
#[derive(uniffi::Record)]
pub struct HybridSigningKeyParts {
    /// ML-DSA parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// ML-DSA public key bytes.
    pub ml_dsa_public_key: Vec<u8>,
    /// Ed25519 public key bytes.
    pub ed25519_public_key: Vec<u8>,
    /// ML-DSA secret key bytes.
    pub ml_dsa_secret_key: Vec<u8>,
    /// Ed25519 secret key bytes.
    pub ed25519_secret_key: Vec<u8>,
}

/// A hybrid signing key. Keys made with `from_seed` are identical on every
/// platform for the same seed, so a seed stored under a wrapped key is all
/// an application needs to persist.
#[derive(uniffi::Object)]
pub struct HybridSigningKey {
    secret: CoreSigSecretKey,
    public: CoreSigPublicKey,
    set: MlDsaParameterSet,
}

impl HybridSigningKey {
    fn wrap(
        public: CoreSigPublicKey,
        secret: CoreSigSecretKey,
    ) -> Result<Arc<Self>, LatticeArcError> {
        let set = secret.parameter_set().try_into()?;
        Ok(Arc::new(Self { secret, public, set }))
    }
}

#[uniffi::export]
impl HybridSigningKey {
    /// Generates a fresh keypair from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// `Internal` if key generation fails.
    #[uniffi::constructor]
    pub fn generate(parameter_set: MlDsaParameterSet) -> Result<Arc<Self>, LatticeArcError> {
        let (public, secret) = generate_keypair_with_parameter_set(parameter_set.into())?;
        Self::wrap(public, secret)
    }

    /// Derives the keypair deterministically from a 32-byte, non-zero seed
    /// (FIPS 204 Algorithm 6 for ML-DSA, RFC 8032 for Ed25519, separated by
    /// HKDF).
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a seed that is not 32 bytes or is all zero.
    #[uniffi::constructor]
    pub fn from_seed(
        seed: &SecretBytes,
        parameter_set: MlDsaParameterSet,
    ) -> Result<Arc<Self>, LatticeArcError> {
        let seed = seed.key32("signing seed")?;
        let (public, secret) = generate_keypair_from_seed(&seed, parameter_set.into())?;
        Self::wrap(public, secret)
    }

    /// Rebuilds a key from parts previously returned by `export_parts`.
    ///
    /// # Errors
    ///
    /// `InvalidParams` or `InvalidInput` when a component has the wrong
    /// length for the parameter set.
    #[uniffi::constructor]
    pub fn from_parts(mut parts: HybridSigningKeyParts) -> Result<Arc<Self>, LatticeArcError> {
        let set: CoreSet = parts.parameter_set.into();
        // Secret halves move into zeroizing wrappers first so every early
        // return below leaves nothing behind in `parts`.
        let ml_dsa_sk = Zeroizing::new(std::mem::take(&mut parts.ml_dsa_secret_key));
        let ed25519_sk = Zeroizing::new(std::mem::take(&mut parts.ed25519_secret_key));
        let public = CoreSigPublicKey::new(
            set,
            std::mem::take(&mut parts.ml_dsa_public_key),
            std::mem::take(&mut parts.ed25519_public_key),
        )?;
        if ml_dsa_sk.len() != set.secret_key_size() {
            return Err(LatticeArcError::invalid_input(format!(
                "ML-DSA secret key must be {} bytes for {set:?}, got {}",
                set.secret_key_size(),
                ml_dsa_sk.len()
            )));
        }
        if ed25519_sk.len() != 32 {
            return Err(LatticeArcError::invalid_input(format!(
                "Ed25519 secret key must be 32 bytes, got {}",
                ed25519_sk.len()
            )));
        }
        let secret = CoreSigSecretKey::new(set, ml_dsa_sk, ed25519_sk);
        Self::wrap(public, secret)
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> Arc<HybridSigPublicKey> {
        Arc::new(HybridSigPublicKey { inner: self.public.clone(), set: self.set })
    }

    /// The ML-DSA parameter set.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.set
    }

    /// Explicitly exports every component. Prefer storing the seed given to
    /// `from_seed`; use this only for keys made with `generate`.
    #[must_use]
    pub fn export_parts(&self) -> HybridSigningKeyParts {
        HybridSigningKeyParts {
            parameter_set: self.set,
            ml_dsa_public_key: self.public.ml_dsa_pk().to_vec(),
            ed25519_public_key: self.public.ed25519_pk().to_vec(),
            ml_dsa_secret_key: take_zeroizing(self.secret.ml_dsa_sk_bytes()),
            ed25519_secret_key: take_zeroizing(self.secret.ed25519_sk_bytes()),
        }
    }

    /// Signs `message` (at most 64 KiB) under a required, non-empty
    /// `context` and returns the wire-encoded hybrid signature.
    ///
    /// # Errors
    ///
    /// `InvalidContext` for an empty or over-long context; `Internal` for a
    /// message over the library's signing size cap (the core reports that
    /// opaquely).
    pub fn sign(&self, message: Vec<u8>, context: Vec<u8>) -> Result<Vec<u8>, LatticeArcError> {
        Ok(sign_with_context(&self.secret, &message, &context)?.to_wire()?)
    }

    /// Signs a caller-computed SHA-512 digest (64 bytes) of content of any
    /// size: HashML-DSA with SHA-512 for the ML-DSA half and Ed25519ph for
    /// the Ed25519 half.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a digest that is not 64 bytes, `InvalidContext`
    /// for an empty or over-long context.
    pub fn sign_prehashed(
        &self,
        digest: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<Vec<u8>, LatticeArcError> {
        Ok(core_sign_prehashed(&self.secret, &digest, &context)?.to_wire()?)
    }
}

/// Verifies a hybrid signature from [`HybridSigningKey::sign`]. Returns
/// `false` for a signature that does not match, including one made under
/// another context or in another mode; both halves must verify.
///
/// # Errors
///
/// `WireFormat` for a malformed signature, `InvalidContext` for an empty or
/// over-long context.
#[uniffi::export]
pub fn verify(
    public_key: &HybridSigPublicKey,
    message: Vec<u8>,
    signature: Vec<u8>,
    context: Vec<u8>,
) -> Result<bool, LatticeArcError> {
    let sig = HybridSignature::from_wire(&signature)?;
    hybrid_verdict(verify_with_context(&public_key.inner, &message, &sig, &context))
}

/// Verifies a signature from [`HybridSigningKey::sign_prehashed`] against
/// the same 64-byte SHA-512 digest.
///
/// # Errors
///
/// `WireFormat` for a malformed signature, `InvalidInput` for a digest that
/// is not 64 bytes, `InvalidContext` for an empty context.
#[uniffi::export]
pub fn verify_prehashed(
    public_key: &HybridSigPublicKey,
    digest: Vec<u8>,
    signature: Vec<u8>,
    context: Vec<u8>,
) -> Result<bool, LatticeArcError> {
    let sig = HybridSignature::from_wire(&signature)?;
    hybrid_verdict(core_verify_prehashed(&public_key.inner, &digest, &sig, &context))
}

// ---------------------------------------------------------------------------
// Single-algorithm ML-DSA
// ---------------------------------------------------------------------------

/// An ML-DSA public key (FIPS 204).
#[derive(uniffi::Object)]
pub struct MlDsaPublicKey {
    inner: CoreMlDsaPublicKey,
    set: MlDsaParameterSet,
}

#[uniffi::export]
impl MlDsaPublicKey {
    /// Builds a public key from its FIPS 204 encoding.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for the wrong length.
    #[uniffi::constructor]
    pub fn from_bytes(
        bytes: Vec<u8>,
        parameter_set: MlDsaParameterSet,
    ) -> Result<Arc<Self>, LatticeArcError> {
        Ok(Arc::new(Self {
            inner: CoreMlDsaPublicKey::from_bytes(&bytes, parameter_set.into())?,
            set: parameter_set,
        }))
    }

    /// The FIPS 204 public key encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// The parameter set.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.set
    }

    /// Verifies a signature from [`MlDsaSigningKey::sign`]. Returns `false`
    /// for a signature that does not match. An empty context is allowed, as
    /// FIPS 204 allows it for plain ML-DSA.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a signature of the wrong length, `InvalidContext`
    /// for a context over 255 bytes.
    pub fn verify(
        &self,
        message: Vec<u8>,
        signature: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<bool, LatticeArcError> {
        check_ml_dsa_context(&context)?;
        let sig = MlDsaSignature::from_bytes(&signature, self.inner.parameter_set())?;
        ml_dsa_verdict(self.inner.verify(&message, &sig, &context))
    }

    /// Verifies a HashML-DSA signature from [`MlDsaSigningKey::sign_prehashed`]
    /// against the same digest and hash choice.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a digest or signature of the wrong length,
    /// `InvalidContext` for an empty or over-long context, `InvalidParams`
    /// for a hash not allowed at this parameter set.
    pub fn verify_prehashed(
        &self,
        digest: Vec<u8>,
        hash: PrehashAlgorithm,
        signature: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<bool, LatticeArcError> {
        check_prehash(self.inner.parameter_set(), hash.into(), &digest, &context)?;
        let sig = MlDsaSignature::from_bytes(&signature, self.inner.parameter_set())?;
        ml_dsa_verdict(self.inner.verify_prehashed(&digest, hash.into(), &sig, &context))
    }
}

/// An ML-DSA signing key.
#[derive(uniffi::Object)]
pub struct MlDsaSigningKey {
    secret: CoreMlDsaSecretKey,
    public: CoreMlDsaPublicKey,
    set: MlDsaParameterSet,
}

#[uniffi::export]
impl MlDsaSigningKey {
    /// Generates a fresh keypair from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// `KeyGeneration` if key generation fails.
    #[uniffi::constructor]
    pub fn generate(parameter_set: MlDsaParameterSet) -> Result<Arc<Self>, LatticeArcError> {
        let (public, secret) = ml_dsa_generate(parameter_set.into())?;
        Ok(Arc::new(Self { secret, public, set: parameter_set }))
    }

    /// Derives the keypair from a 32-byte seed (FIPS 204 Algorithm 6).
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a seed that is not 32 bytes.
    #[uniffi::constructor]
    pub fn from_seed(
        seed: &SecretBytes,
        parameter_set: MlDsaParameterSet,
    ) -> Result<Arc<Self>, LatticeArcError> {
        let seed = seed.key32("ML-DSA seed")?;
        let (public, secret) = ml_dsa_generate_from_seed(parameter_set.into(), &seed)?;
        Ok(Arc::new(Self { secret, public, set: parameter_set }))
    }

    /// Rebuilds a signing key from the FIPS 204 encodings of its secret and
    /// public halves.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for the wrong lengths.
    #[uniffi::constructor]
    pub fn from_parts(
        secret_key: &SecretBytes,
        public_key: Vec<u8>,
        parameter_set: MlDsaParameterSet,
    ) -> Result<Arc<Self>, LatticeArcError> {
        let set: CoreSet = parameter_set.into();
        let secret = CoreMlDsaSecretKey::from_bytes(secret_key.expose(), set)?;
        let public = CoreMlDsaPublicKey::from_bytes(&public_key, set)?;
        Ok(Arc::new(Self { secret, public, set: parameter_set }))
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> Arc<MlDsaPublicKey> {
        Arc::new(MlDsaPublicKey { inner: self.public.clone(), set: self.set })
    }

    /// The parameter set.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.set
    }

    /// Explicitly exports the FIPS 204 secret key encoding.
    #[must_use]
    pub fn export_secret_key(&self) -> Arc<SecretBytes> {
        SecretBytes::from_vec(take_zeroizing(self.secret.to_bytes()))
    }

    /// Signs `message` (at most 64 KiB) with a context of up to 255 bytes.
    /// An empty context is allowed, as FIPS 204 allows it for plain ML-DSA.
    ///
    /// # Errors
    ///
    /// `InvalidContext` for an over-long context; `Internal` for a message
    /// over the library's signing size cap (the core reports that opaquely).
    pub fn sign(&self, message: Vec<u8>, context: Vec<u8>) -> Result<Vec<u8>, LatticeArcError> {
        check_ml_dsa_context(&context)?;
        Ok(self.secret.sign(&message, &context)?.to_bytes())
    }

    /// HashML-DSA (FIPS 204 Algorithm 4): signs a caller-computed digest of
    /// content of any size. `context` must be non-empty and at most 255
    /// bytes.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a digest of the wrong length for `hash`,
    /// `InvalidContext` for an empty or over-long context, `InvalidParams`
    /// for a hash not allowed at this parameter set.
    pub fn sign_prehashed(
        &self,
        digest: Vec<u8>,
        hash: PrehashAlgorithm,
        context: Vec<u8>,
    ) -> Result<Vec<u8>, LatticeArcError> {
        check_prehash(self.secret.parameter_set(), hash.into(), &digest, &context)?;
        Ok(self.secret.sign_prehashed(&digest, hash.into(), &context)?.to_bytes())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
#[expect(clippy::indexing_slicing, reason = "Tests index into buffers of known length")]
mod tests {
    use super::*;
    use sha2::{Digest, Sha512};

    fn seed(fill: u8) -> Arc<SecretBytes> {
        SecretBytes::import(vec![fill; 32])
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let sk = HybridSigningKey::generate(MlDsaParameterSet::MlDsa65).unwrap();
        assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa65);
        let pk = HybridSigPublicKey::from_wire(sk.public_key().to_wire().unwrap()).unwrap();
        let sig = sk.sign(b"msg".to_vec(), b"app/v1".to_vec()).unwrap();
        assert!(verify(&pk, b"msg".to_vec(), sig.clone(), b"app/v1".to_vec()).unwrap());
        assert!(!verify(&pk, b"msg2".to_vec(), sig.clone(), b"app/v1".to_vec()).unwrap());
        assert!(!verify(&pk, b"msg".to_vec(), sig.clone(), b"app/v2".to_vec()).unwrap());
        assert!(matches!(
            verify(&pk, b"msg".to_vec(), sig[..10].to_vec(), b"app/v1".to_vec()),
            Err(LatticeArcError::WireFormat { .. })
        ));
        assert!(matches!(
            sk.sign(b"m".to_vec(), vec![]),
            Err(LatticeArcError::InvalidContext { .. })
        ));
    }

    #[test]
    fn hybrid_prehashed_roundtrip_and_mode_separation() {
        let sk = HybridSigningKey::from_seed(&seed(7), MlDsaParameterSet::MlDsa44).unwrap();
        let pk = sk.public_key();
        let digest: Vec<u8> = Sha512::digest(b"large content").to_vec();
        let sig = sk.sign_prehashed(digest.clone(), b"root".to_vec()).unwrap();
        assert!(verify_prehashed(&pk, digest.clone(), sig.clone(), b"root".to_vec()).unwrap());
        assert!(!verify_prehashed(&pk, digest.clone(), sig.clone(), b"other".to_vec()).unwrap());
        // A pre-hashed signature never verifies as a plain one and vice versa.
        assert!(!verify(&pk, digest, sig, b"root".to_vec()).unwrap());
        assert!(matches!(
            sk.sign_prehashed(vec![0; 32], b"root".to_vec()),
            Err(LatticeArcError::InvalidInput { .. })
        ));
    }

    #[test]
    fn hybrid_seed_is_deterministic_and_parts_roundtrip() {
        let a = HybridSigningKey::from_seed(&seed(1), MlDsaParameterSet::MlDsa87).unwrap();
        let b = HybridSigningKey::from_seed(&seed(1), MlDsaParameterSet::MlDsa87).unwrap();
        assert_eq!(a.public_key().to_wire().unwrap(), b.public_key().to_wire().unwrap());
        assert_eq!(a.export_parts().ml_dsa_secret_key, b.export_parts().ml_dsa_secret_key);
        assert_eq!(a.export_parts().ed25519_secret_key, b.export_parts().ed25519_secret_key);
        let c = HybridSigningKey::from_seed(&seed(2), MlDsaParameterSet::MlDsa87).unwrap();
        assert_ne!(a.public_key().to_wire().unwrap(), c.public_key().to_wire().unwrap());

        assert!(matches!(
            HybridSigningKey::from_seed(&seed(0), MlDsaParameterSet::MlDsa65),
            Err(LatticeArcError::InvalidInput { .. })
        ));
        assert!(matches!(
            HybridSigningKey::from_seed(
                &SecretBytes::import(vec![1; 16]),
                MlDsaParameterSet::MlDsa65
            ),
            Err(LatticeArcError::InvalidInput { .. })
        ));

        let back = HybridSigningKey::from_parts(a.export_parts()).unwrap();
        let sig = back.sign(b"m".to_vec(), b"c".to_vec()).unwrap();
        assert!(verify(&a.public_key(), b"m".to_vec(), sig, b"c".to_vec()).unwrap());
        let mut bad = a.export_parts();
        bad.ed25519_secret_key.pop();
        assert!(matches!(
            HybridSigningKey::from_parts(bad),
            Err(LatticeArcError::InvalidInput { .. })
        ));
    }

    #[test]
    fn ml_dsa_roundtrip_plain_and_prehashed() {
        let sk = MlDsaSigningKey::from_seed(&seed(9), MlDsaParameterSet::MlDsa65).unwrap();
        let pk = MlDsaPublicKey::from_bytes(sk.public_key().to_bytes(), MlDsaParameterSet::MlDsa65)
            .unwrap();
        assert_eq!(pk.parameter_set(), MlDsaParameterSet::MlDsa65);
        let sig = sk.sign(b"msg".to_vec(), b"ctx".to_vec()).unwrap();
        assert!(pk.verify(b"msg".to_vec(), sig.clone(), b"ctx".to_vec()).unwrap());
        assert!(!pk.verify(b"msg".to_vec(), sig, b"other".to_vec()).unwrap());

        let digest: Vec<u8> = Sha512::digest(b"big").to_vec();
        let sig =
            sk.sign_prehashed(digest.clone(), PrehashAlgorithm::Sha512, b"ctx".to_vec()).unwrap();
        assert!(
            pk.verify_prehashed(
                digest.clone(),
                PrehashAlgorithm::Sha512,
                sig.clone(),
                b"ctx".to_vec()
            )
            .unwrap()
        );
        assert!(
            !pk.verify_prehashed(
                digest.clone(),
                PrehashAlgorithm::Sha512,
                sig.clone(),
                b"x".to_vec()
            )
            .unwrap()
        );
        // Misconfiguration is typed, not an opaque failure or a `false`.
        assert!(matches!(
            sk.sign_prehashed(vec![0; 32], PrehashAlgorithm::Sha256, b"ctx".to_vec()),
            Err(LatticeArcError::InvalidParams { .. })
        ));
        assert!(matches!(
            pk.verify_prehashed(
                vec![0; 32],
                PrehashAlgorithm::Sha256,
                sig.clone(),
                b"ctx".to_vec()
            ),
            Err(LatticeArcError::InvalidParams { .. })
        ));
        assert!(matches!(
            sk.sign_prehashed(digest.clone(), PrehashAlgorithm::Sha512, vec![]),
            Err(LatticeArcError::InvalidContext { .. })
        ));
        assert!(matches!(
            pk.verify_prehashed(digest, PrehashAlgorithm::Sha512, sig.clone(), vec![0; 256]),
            Err(LatticeArcError::InvalidContext { .. })
        ));
        assert!(matches!(
            sk.sign_prehashed(vec![0; 32], PrehashAlgorithm::Sha512, b"ctx".to_vec()),
            Err(LatticeArcError::InvalidInput { .. })
        ));
        assert!(matches!(
            pk.verify_prehashed(vec![0; 16], PrehashAlgorithm::Sha512, sig, b"ctx".to_vec()),
            Err(LatticeArcError::InvalidInput { .. })
        ));
        assert!(matches!(
            sk.sign(b"m".to_vec(), vec![0; 256]),
            Err(LatticeArcError::InvalidContext { .. })
        ));
        // Plain ML-DSA accepts an empty context (FIPS 204).
        let plain = sk.sign(b"m".to_vec(), vec![]).unwrap();
        assert!(pk.verify(b"m".to_vec(), plain, vec![]).unwrap());
    }

    #[test]
    fn ml_dsa_seed_deterministic_and_parts_roundtrip() {
        let a = MlDsaSigningKey::from_seed(&seed(3), MlDsaParameterSet::MlDsa44).unwrap();
        let b = MlDsaSigningKey::from_seed(&seed(3), MlDsaParameterSet::MlDsa44).unwrap();
        assert_eq!(a.public_key().to_bytes(), b.public_key().to_bytes());
        assert_eq!(a.export_secret_key().export_bytes(), b.export_secret_key().export_bytes());
        let g = MlDsaSigningKey::generate(MlDsaParameterSet::MlDsa44).unwrap();
        let back = MlDsaSigningKey::from_parts(
            &g.export_secret_key(),
            g.public_key().to_bytes(),
            MlDsaParameterSet::MlDsa44,
        )
        .unwrap();
        let sig = back.sign(b"m".to_vec(), vec![]).unwrap();
        assert!(g.public_key().verify(b"m".to_vec(), sig, vec![]).unwrap());
        assert!(matches!(
            MlDsaSigningKey::from_parts(&seed(1), vec![], MlDsaParameterSet::MlDsa44),
            Err(LatticeArcError::InvalidInput { .. })
        ));
    }
}
