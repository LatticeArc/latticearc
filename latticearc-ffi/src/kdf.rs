//! Key derivation: Argon2id (RFC 9106), HKDF and SP 800-108 counter mode,
//! each with a required domain-separation context.

use std::sync::Arc;

use latticearc::primitives::kdf::argon2id::{
    Argon2Params as CoreArgon2Params, argon2id as core_argon2id,
};
use latticearc::primitives::kdf::{counter_kdf_with_context, hkdf_with_context};

use crate::error::LatticeArcError;
use crate::secrets::SecretBytes;

/// Largest output [`hkdf`] and [`counter_kdf`] will derive, in bytes: the
/// HKDF-SHA256 maximum (255 x 32). The core counter KDF would accept up to
/// 512 MiB; a foreign caller gets the same bound for both so a bad `length`
/// cannot allocate that much on a phone.
pub const MAX_KDF_OUTPUT_LEN: u32 = 8160;

fn check_kdf_length(length: u32) -> Result<usize, LatticeArcError> {
    if length == 0 || length > MAX_KDF_OUTPUT_LEN {
        return Err(LatticeArcError::InvalidParams {
            reason: format!("derived key length must be 1..={MAX_KDF_OUTPUT_LEN}, got {length}"),
        });
    }
    Ok(length as usize)
}

/// Argon2id cost parameters.
///
/// `memory_kib` is the memory per derivation in KiB, `iterations` the number
/// of passes, `parallelism` the lane count and `output_len` the derived key
/// length in bytes (16..=1024). Start from [`argon2_default_params`] or
/// measure with [`argon2_calibrate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Argon2Params {
    /// Memory per derivation in KiB.
    pub memory_kib: u32,
    /// Number of passes over the memory.
    pub iterations: u32,
    /// Lane count.
    pub parallelism: u32,
    /// Derived key length in bytes.
    pub output_len: u32,
}

impl From<CoreArgon2Params> for Argon2Params {
    fn from(p: CoreArgon2Params) -> Self {
        Self {
            memory_kib: p.memory_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
            output_len: u32::try_from(p.output_len).unwrap_or(u32::MAX),
        }
    }
}

impl TryFrom<Argon2Params> for CoreArgon2Params {
    type Error = LatticeArcError;

    fn try_from(p: Argon2Params) -> Result<Self, Self::Error> {
        Ok(Self::new(p.memory_kib, p.iterations, p.parallelism, p.output_len as usize)?)
    }
}

/// The library's default Argon2id profile: 64 MiB, 3 passes, 1 lane,
/// 32-byte key (RFC 9106 §4 second recommended option, sized for phones).
#[uniffi::export]
#[must_use]
pub fn argon2_default_params() -> Argon2Params {
    CoreArgon2Params::default().into()
}

/// Measures this device and returns parameters that take about `target_ms`
/// milliseconds per derivation without exceeding `max_memory_kib`.
///
/// # Errors
///
/// `InvalidParams` when the target or the memory bound is outside the
/// supported range.
#[uniffi::export]
pub fn argon2_calibrate(
    target_ms: u64,
    max_memory_kib: u32,
) -> Result<Argon2Params, LatticeArcError> {
    Ok(CoreArgon2Params::calibrate(target_ms, max_memory_kib)?.into())
}

/// Derives a key from `password` and `salt` (at least 8 bytes, 16
/// recommended) with Argon2id.
///
/// # Errors
///
/// `InvalidParams` for parameters outside the RFC 9106 ranges, a salt under
/// 8 bytes or an empty password; `ResourceLimit` when `memory_kib` exceeds
/// the process-wide Argon2 memory cap. A derivation at the default profile
/// takes a noticeable fraction of a second: run it off the UI thread.
#[uniffi::export]
pub fn argon2id(
    password: &SecretBytes,
    salt: Vec<u8>,
    params: Argon2Params,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    let core_params = CoreArgon2Params::try_from(params)?;
    let derived = core_argon2id(password.expose(), &salt, &core_params)?;
    Ok(SecretBytes::from_vec(derived.expose_secret().to_vec()))
}

/// HKDF-SHA256 extract-and-expand with a required, non-empty `context`
/// (the HKDF `info`). `salt` may be omitted.
///
/// # Errors
///
/// `InvalidContext` when `context` is empty; `InvalidParams` when `length`
/// is zero or above [`MAX_KDF_OUTPUT_LEN`].
#[uniffi::export]
pub fn hkdf(
    ikm: &SecretBytes,
    salt: Option<Vec<u8>>,
    context: Vec<u8>,
    length: u32,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    if context.is_empty() {
        return Err(LatticeArcError::InvalidContext {
            reason: "HKDF context must not be empty".to_string(),
        });
    }
    let length = check_kdf_length(length)?;
    let out = hkdf_with_context(ikm.expose(), salt.as_deref(), &context, length)?;
    Ok(SecretBytes::from_vec(out.expose_secret().to_vec()))
}

/// SP 800-108 KDF in counter mode (HMAC-SHA256) with a required `label`
/// and a required, non-empty `context`.
///
/// # Errors
///
/// `InvalidContext` when `label` or `context` is empty; `InvalidParams`
/// when `length` is zero or above [`MAX_KDF_OUTPUT_LEN`].
#[uniffi::export]
pub fn counter_kdf(
    key: &SecretBytes,
    label: Vec<u8>,
    context: Vec<u8>,
    length: u32,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    if label.is_empty() || context.is_empty() {
        return Err(LatticeArcError::InvalidContext {
            reason: "SP 800-108 label and context must not be empty".to_string(),
        });
    }
    let length = check_kdf_length(length)?;
    let out = counter_kdf_with_context(key.expose(), &label, &context, length)?;
    Ok(SecretBytes::from_vec(out.expose_secret().to_vec()))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
mod tests {
    use super::*;

    fn small_params() -> Argon2Params {
        Argon2Params { memory_kib: 1024, iterations: 1, parallelism: 1, output_len: 32 }
    }

    #[test]
    fn default_params_match_core_profile() {
        let p = argon2_default_params();
        assert_eq!(p, CoreArgon2Params::default().into());
        assert_eq!(p.output_len, 32);
    }

    #[test]
    fn argon2id_is_deterministic_and_salt_sensitive() {
        let pw = SecretBytes::import(b"correct horse".to_vec());
        let a = argon2id(&pw, vec![1u8; 16], small_params()).unwrap();
        let b = argon2id(&pw, vec![1u8; 16], small_params()).unwrap();
        let c = argon2id(&pw, vec![2u8; 16], small_params()).unwrap();
        assert_eq!(a.export_bytes(), b.export_bytes());
        assert_ne!(a.export_bytes(), c.export_bytes());
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn argon2id_matches_core_call() {
        let pw = SecretBytes::import(b"pw".to_vec());
        let ours = argon2id(&pw, vec![3u8; 16], small_params()).unwrap();
        let core =
            core_argon2id(b"pw", &[3u8; 16], &CoreArgon2Params::try_from(small_params()).unwrap())
                .unwrap();
        assert_eq!(ours.export_bytes(), core.expose_secret());
    }

    #[test]
    fn argon2id_rejects_bad_params_and_short_salt() {
        let pw = SecretBytes::import(b"pw".to_vec());
        let bad = Argon2Params { iterations: 0, ..small_params() };
        assert!(matches!(
            argon2id(&pw, vec![1u8; 16], bad),
            Err(LatticeArcError::InvalidParams { .. })
        ));
        let r = argon2id(&pw, vec![1u8; 4], small_params());
        assert!(r.is_err());
    }

    #[test]
    fn calibrate_respects_memory_bound() {
        let p = argon2_calibrate(20, 2048).unwrap();
        assert!(p.memory_kib <= 2048);
        assert!(p.iterations >= 1);
    }

    #[test]
    fn hkdf_requires_context_and_is_deterministic() {
        let ikm = SecretBytes::import(vec![0x0b; 22]);
        assert!(matches!(
            hkdf(&ikm, None, vec![], 32),
            Err(LatticeArcError::InvalidContext { .. })
        ));
        let a = hkdf(&ikm, Some(vec![1, 2, 3]), b"app/v1".to_vec(), 42).unwrap();
        let b = hkdf(&ikm, Some(vec![1, 2, 3]), b"app/v1".to_vec(), 42).unwrap();
        assert_eq!(a.len(), 42);
        assert_eq!(a.export_bytes(), b.export_bytes());
        let core = hkdf_with_context(&[0x0b; 22], Some(&[1, 2, 3]), b"app/v1", 42).unwrap();
        assert_eq!(a.export_bytes(), core.expose_secret());
    }

    #[test]
    fn counter_kdf_requires_label_and_context() {
        let key = SecretBytes::import(vec![0x42; 32]);
        assert!(matches!(
            counter_kdf(&key, vec![], b"ctx".to_vec(), 32),
            Err(LatticeArcError::InvalidContext { .. })
        ));
        assert!(matches!(
            counter_kdf(&key, b"label".to_vec(), vec![], 32),
            Err(LatticeArcError::InvalidContext { .. })
        ));
        let out = counter_kdf(&key, b"label".to_vec(), b"ctx".to_vec(), 32).unwrap();
        let core = counter_kdf_with_context(&[0x42; 32], b"label", b"ctx", 32).unwrap();
        assert_eq!(out.export_bytes(), core.expose_secret());
    }

    #[test]
    fn kdf_output_lengths_are_capped() {
        let key = SecretBytes::import(vec![0x42; 32]);
        for len in [0u32, MAX_KDF_OUTPUT_LEN + 1, u32::MAX] {
            assert!(matches!(
                counter_kdf(&key, b"label".to_vec(), b"ctx".to_vec(), len),
                Err(LatticeArcError::InvalidParams { .. })
            ));
            assert!(matches!(
                hkdf(&key, None, b"ctx".to_vec(), len),
                Err(LatticeArcError::InvalidParams { .. })
            ));
        }
        assert_eq!(
            counter_kdf(&key, b"label".to_vec(), b"ctx".to_vec(), MAX_KDF_OUTPUT_LEN)
                .unwrap()
                .len(),
            MAX_KDF_OUTPUT_LEN
        );
    }
}
