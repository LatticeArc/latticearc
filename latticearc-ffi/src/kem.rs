//! Hybrid ML-KEM + X25519 key encapsulation and hybrid public-key
//! encryption, with the LatticeArc wire format for everything public.

use std::sync::Arc;

use latticearc::hybrid::encrypt_hybrid::{
    HybridCiphertext, HybridEncryptionContext, decrypt_hybrid as core_decrypt_hybrid,
    encrypt_hybrid as core_encrypt_hybrid,
};
use latticearc::hybrid::kem_hybrid::{
    EncapsulatedKey, HybridKemPublicKey as CoreKemPublicKey,
    HybridKemSecretKey as CoreKemSecretKey, decapsulate_with_context, encapsulate_with_context,
    generate_keypair_with_level,
};
use latticearc::hybrid::wire::WireEncode;
use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel as CoreLevel;

use zeroize::{Zeroize, Zeroizing};

use crate::error::LatticeArcError;
use crate::secrets::{SecretBytes, take_zeroizing};

/// ML-KEM parameter set of the post-quantum half of a hybrid key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MlKemSecurityLevel {
    /// ML-KEM-512 (NIST category 1).
    MlKem512,
    /// ML-KEM-768 (NIST category 3), the default.
    MlKem768,
    /// ML-KEM-1024 (NIST category 5).
    MlKem1024,
}

impl From<MlKemSecurityLevel> for CoreLevel {
    fn from(l: MlKemSecurityLevel) -> Self {
        match l {
            MlKemSecurityLevel::MlKem512 => Self::MlKem512,
            MlKemSecurityLevel::MlKem768 => Self::MlKem768,
            MlKemSecurityLevel::MlKem1024 => Self::MlKem1024,
        }
    }
}

impl TryFrom<CoreLevel> for MlKemSecurityLevel {
    type Error = LatticeArcError;

    fn try_from(l: CoreLevel) -> Result<Self, Self::Error> {
        match l {
            CoreLevel::MlKem512 => Ok(Self::MlKem512),
            CoreLevel::MlKem768 => Ok(Self::MlKem768),
            CoreLevel::MlKem1024 => Ok(Self::MlKem1024),
            _ => Err(LatticeArcError::internal(format!("unsupported ML-KEM level {l:?}"))),
        }
    }
}

/// A hybrid KEM public key (ML-KEM encapsulation key + X25519 public key).
#[derive(uniffi::Object)]
pub struct HybridKemPublicKey {
    inner: CoreKemPublicKey,
    level: MlKemSecurityLevel,
}

impl HybridKemPublicKey {
    fn wrap(inner: CoreKemPublicKey) -> Result<Arc<Self>, LatticeArcError> {
        let level = inner.security_level().try_into()?;
        Ok(Arc::new(Self { inner, level }))
    }
}

#[uniffi::export]
impl HybridKemPublicKey {
    /// Parses the LatticeArc wire encoding produced by `to_wire`.
    ///
    /// # Errors
    ///
    /// `WireFormat` for anything that is not a well-formed public key.
    #[uniffi::constructor]
    pub fn from_wire(bytes: Vec<u8>) -> Result<Arc<Self>, LatticeArcError> {
        Self::wrap(CoreKemPublicKey::from_wire(&bytes)?)
    }

    /// The versioned wire encoding (see `docs/WIRE_FORMAT.md`).
    ///
    /// # Errors
    ///
    /// `WireFormat` if the key's components have inconsistent lengths.
    pub fn to_wire(&self) -> Result<Vec<u8>, LatticeArcError> {
        Ok(self.inner.to_wire()?)
    }

    /// The ML-KEM parameter set.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.level
    }
}

/// The components of a hybrid KEM secret key, returned only by
/// [`HybridKemSecretKey::export_parts`].
///
/// This is an explicit export: the fields are plain byte strings the caller
/// now owns and must clear after persisting them. The record is not
/// comparable, cloneable or printable, so secrets cannot leak through
/// equality checks or logs.
#[derive(uniffi::Record)]
pub struct HybridKemSecretKeyParts {
    /// ML-KEM parameter set.
    pub security_level: MlKemSecurityLevel,
    /// ML-KEM decapsulation key bytes.
    pub ml_kem_secret_key: Vec<u8>,
    /// ML-KEM encapsulation key bytes.
    pub ml_kem_public_key: Vec<u8>,
    /// 32-byte X25519 seed.
    pub ecdh_seed: Vec<u8>,
}

/// A hybrid KEM secret key. Generate one with
/// [`HybridKemSecretKey::generate`]; it never leaves Rust except through
/// `export_parts`.
#[derive(uniffi::Object)]
pub struct HybridKemSecretKey {
    inner: CoreKemSecretKey,
    level: MlKemSecurityLevel,
}

impl HybridKemSecretKey {
    fn wrap(inner: CoreKemSecretKey) -> Result<Arc<Self>, LatticeArcError> {
        let level = inner.security_level().try_into()?;
        Ok(Arc::new(Self { inner, level }))
    }
}

#[uniffi::export]
impl HybridKemSecretKey {
    /// Generates a fresh keypair at `level` from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// `Internal` if the underlying key generation fails.
    #[uniffi::constructor]
    pub fn generate(level: MlKemSecurityLevel) -> Result<Arc<Self>, LatticeArcError> {
        let (_pk, sk) = generate_keypair_with_level(level.into())?;
        Self::wrap(sk)
    }

    /// Rebuilds a key from parts previously returned by `export_parts`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when a component has the wrong length for `level`.
    #[uniffi::constructor]
    pub fn from_parts(mut parts: HybridKemSecretKeyParts) -> Result<Arc<Self>, LatticeArcError> {
        let seed_len = parts.ecdh_seed.len();
        let seed: Zeroizing<[u8; 32]> =
            parts.ecdh_seed.as_slice().try_into().map(Zeroizing::new).map_err(|_e| {
                LatticeArcError::invalid_input(format!(
                    "ecdh seed must be 32 bytes, got {seed_len}"
                ))
            })?;
        let result = CoreKemSecretKey::from_serialized(
            parts.security_level.into(),
            &parts.ml_kem_secret_key,
            &parts.ml_kem_public_key,
            &seed,
        );
        // Nothing secret stays behind in the caller's record once the key
        // object exists (or the parts were rejected).
        parts.ml_kem_secret_key.zeroize();
        parts.ecdh_seed.zeroize();
        Self::wrap(result?)
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> Arc<HybridKemPublicKey> {
        Arc::new(HybridKemPublicKey {
            inner: CoreKemPublicKey::new(
                self.inner.ml_kem_pk_bytes(),
                self.inner.ecdh_public_key_bytes(),
                self.inner.security_level(),
            ),
            level: self.level,
        })
    }

    /// The ML-KEM parameter set.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.level
    }

    /// Explicitly exports the secret components, for storage under a
    /// wrapped key. Clear the result as soon as it is persisted.
    ///
    /// # Errors
    ///
    /// `Internal` if the ML-KEM key cannot be serialized.
    pub fn export_parts(&self) -> Result<HybridKemSecretKeyParts, LatticeArcError> {
        Ok(HybridKemSecretKeyParts {
            security_level: self.level,
            ml_kem_secret_key: take_zeroizing(self.inner.ml_kem_sk_bytes()?),
            ml_kem_public_key: self.inner.ml_kem_pk_bytes(),
            ecdh_seed: self.inner.ecdh_seed_bytes()?.to_vec(),
        })
    }
}

/// Result of [`encapsulate`]: the public encapsulated key to send, and the
/// shared secret to keep.
#[derive(uniffi::Record)]
pub struct Encapsulation {
    /// Wire-encoded encapsulated key (ML-KEM ciphertext + ephemeral X25519
    /// public key); pass it to [`decapsulate`].
    pub encapsulated_key: Vec<u8>,
    /// The 64-byte shared secret.
    pub shared_secret: Arc<SecretBytes>,
}

/// Encapsulates a fresh shared secret to `public_key`. `context` is
/// required and non-empty; the same context must be used to decapsulate.
///
/// # Errors
///
/// `InvalidContext` for an empty or over-long context.
#[uniffi::export]
pub fn encapsulate(
    public_key: &HybridKemPublicKey,
    context: Vec<u8>,
) -> Result<Encapsulation, LatticeArcError> {
    let enc = encapsulate_with_context(&public_key.inner, &context)?;
    let shared_secret = SecretBytes::from_vec(enc.expose_secret().to_vec());
    Ok(Encapsulation { encapsulated_key: enc.to_wire()?, shared_secret })
}

/// Recovers the shared secret from a wire-encoded encapsulated key.
///
/// ML-KEM uses implicit rejection: a well-formed encapsulated key that was
/// made for another secret key, or decapsulated under another `context`,
/// yields a *different* 64-byte secret with no error. Key confirmation must
/// come from the authenticated step that uses the secret (for example
/// [`decrypt_hybrid`] or an AEAD), never from this call succeeding.
///
/// # Errors
///
/// `WireFormat` for a malformed encapsulated key, `InvalidContext` for an
/// empty context.
#[uniffi::export]
pub fn decapsulate(
    secret_key: &HybridKemSecretKey,
    encapsulated_key: Vec<u8>,
    context: Vec<u8>,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    let enc = EncapsulatedKey::from_wire(&encapsulated_key)?;
    let ss = decapsulate_with_context(&secret_key.inner, &enc, &context)?;
    Ok(SecretBytes::from_vec(ss.expose_secret().to_vec()))
}

/// Encrypts `plaintext` to `public_key` (hybrid KEM + AES-256-GCM) and
/// returns the wire-encoded ciphertext. `aad` is authenticated but not
/// encrypted.
///
/// # Errors
///
/// `InvalidInput` for plaintext above the library's size cap.
#[uniffi::export]
pub fn encrypt_hybrid(
    public_key: &HybridKemPublicKey,
    plaintext: Vec<u8>,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, LatticeArcError> {
    let ctx = aad.map(HybridEncryptionContext::with_aad);
    let ct = core_encrypt_hybrid(&public_key.inner, &plaintext, ctx.as_ref())?;
    Ok(ct.to_wire()?)
}

/// Decrypts a ciphertext from [`encrypt_hybrid`].
///
/// # Errors
///
/// `WireFormat` for a malformed ciphertext, `AuthenticationFailed` for a
/// wrong key, wrong `aad` or tampered bytes.
#[uniffi::export]
pub fn decrypt_hybrid(
    secret_key: &HybridKemSecretKey,
    ciphertext: Vec<u8>,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, LatticeArcError> {
    let ct = HybridCiphertext::from_wire(&ciphertext)?;
    let ctx = aad.map(HybridEncryptionContext::with_aad);
    Ok(take_zeroizing(core_decrypt_hybrid(&secret_key.inner, &ct, ctx.as_ref())?))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
#[expect(clippy::indexing_slicing, reason = "Tests index into buffers of known length")]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip_all_levels() {
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let sk = HybridKemSecretKey::generate(level).unwrap();
            assert_eq!(sk.security_level(), level);
            let pk = HybridKemPublicKey::from_wire(sk.public_key().to_wire().unwrap()).unwrap();
            assert_eq!(pk.security_level(), level);
            let enc = encapsulate(&pk, b"app/v1/transfer".to_vec()).unwrap();
            assert_eq!(enc.shared_secret.len(), 64);
            let ss = decapsulate(&sk, enc.encapsulated_key, b"app/v1/transfer".to_vec()).unwrap();
            assert_eq!(ss.export_bytes(), enc.shared_secret.export_bytes());
        }
    }

    #[test]
    fn kem_context_is_required_and_bound() {
        let sk = HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem768).unwrap();
        let pk = sk.public_key();
        assert!(matches!(encapsulate(&pk, vec![]), Err(LatticeArcError::InvalidContext { .. })));
        let enc = encapsulate(&pk, b"a".to_vec()).unwrap();
        let other = decapsulate(&sk, enc.encapsulated_key.clone(), b"b".to_vec()).unwrap();
        assert_ne!(other.export_bytes(), enc.shared_secret.export_bytes());
        // Implicit rejection: a wrong secret key also yields a different
        // secret without an error.
        let wrong = HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem768).unwrap();
        let implicit = decapsulate(&wrong, enc.encapsulated_key, b"a".to_vec()).unwrap();
        assert_ne!(implicit.export_bytes(), enc.shared_secret.export_bytes());
    }

    #[test]
    fn secret_key_parts_roundtrip() {
        let sk = HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem768).unwrap();
        let parts = sk.export_parts().unwrap();
        assert_eq!(parts.ecdh_seed.len(), 32);
        let back = HybridKemSecretKey::from_parts(parts).unwrap();
        let again = back.export_parts().unwrap();
        let original = sk.export_parts().unwrap();
        assert_eq!(again.ml_kem_secret_key, original.ml_kem_secret_key);
        assert_eq!(again.ecdh_seed, original.ecdh_seed);
        assert_eq!(back.public_key().to_wire().unwrap(), sk.public_key().to_wire().unwrap());

        let mut bad = sk.export_parts().unwrap();
        bad.ecdh_seed.pop();
        assert!(matches!(
            HybridKemSecretKey::from_parts(bad),
            Err(LatticeArcError::InvalidInput { .. })
        ));
    }

    #[test]
    fn hybrid_encrypt_decrypt_roundtrip_and_failures() {
        let sk = HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem768).unwrap();
        let pk = sk.public_key();
        let ct = encrypt_hybrid(&pk, b"hello".to_vec(), Some(b"hdr".to_vec())).unwrap();
        assert_eq!(decrypt_hybrid(&sk, ct.clone(), Some(b"hdr".to_vec())).unwrap(), b"hello");
        assert_eq!(
            decrypt_hybrid(&sk, ct.clone(), Some(b"other".to_vec())).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        let other = HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem768).unwrap();
        assert_eq!(
            decrypt_hybrid(&other, ct.clone(), Some(b"hdr".to_vec())).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            decrypt_hybrid(&sk, tampered, Some(b"hdr".to_vec())).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        assert!(matches!(
            decrypt_hybrid(&sk, ct[..7].to_vec(), None),
            Err(LatticeArcError::WireFormat { .. })
        ));
        let no_aad = encrypt_hybrid(&pk, vec![], None).unwrap();
        assert_eq!(decrypt_hybrid(&sk, no_aad, None).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn wire_rejects_garbage() {
        assert!(matches!(
            HybridKemPublicKey::from_wire(vec![0; 3]),
            Err(LatticeArcError::WireFormat { .. })
        ));
        let sk = HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem512).unwrap();
        assert!(matches!(
            decapsulate(&sk, b"LA\x01junk".to_vec(), b"c".to_vec()),
            Err(LatticeArcError::WireFormat { .. })
        ));
    }
}
