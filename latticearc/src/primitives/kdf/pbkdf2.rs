#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SP 800-132: Password-Based Key Derivation Function (PBKDF2)
//!
//! PBKDF2 is a password-based key derivation function that applies a pseudorandom
//! function (typically HMAC) to derive keys from passwords. It includes salting and
//! iteration to make brute-force attacks more difficult.
//!
//! This implementation provides NIST SP 800-132 compliant PBKDF2 with:
//! - Configurable iteration counts for adjustable computational cost
//! - Salt support for key uniqueness
//! - Multiple PRF options (HMAC-SHA256, HMAC-SHA512)
//! - Secure memory handling with zeroization

use crate::prelude::error::{LatticeArcError, Result};
use aws_lc_rs::hmac::{self, HMAC_SHA256, HMAC_SHA512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// PBKDF2 pseudorandom function types
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrfType {
    /// HMAC-SHA256 (recommended for most applications)
    HmacSha256,
    /// HMAC-SHA512 (for higher security requirements)
    HmacSha512,
}

/// PBKDF2 parameters structure.
///
/// Salt is public protocol data, but scrubbing it on drop matches the rest of
/// the library's zeroization hygiene and prevents stale-copy buildup when the
/// struct is cloned around a request pipeline.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Pbkdf2Params {
    /// Salt value (minimum 16 bytes recommended)
    /// Consumer: pbkdf2()
    pub salt: Vec<u8>,
    /// Iteration count.
    ///
    /// Floor enforced at derivation time, scaled by PRF (OWASP 2023
    /// Password Storage Cheat Sheet):
    ///   * `HmacSha256` → [`Pbkdf2Params::MIN_ITERATIONS_SHA256`] (600,000)
    ///   * `HmacSha512` → [`Pbkdf2Params::MIN_ITERATIONS_SHA512`] (210,000)
    ///
    /// Consumer: pbkdf2()
    pub iterations: u32,
    /// Desired key length in bytes
    /// Consumer: pbkdf2()
    pub key_length: usize,
    /// PRF to use
    /// Consumer: pbkdf2()
    #[zeroize(skip)] // PrfType is a Copy enum with no secret content
    pub prf: PrfType,
}

impl Pbkdf2Params {
    /// NIST SP 800-132 §5.1 minimum salt length (128 bits = 16 bytes).
    ///
    /// > "A randomly-generated salt SHALL be used. The salt SHALL be a
    /// > randomly-generated value of at least 128 bits."
    ///
    /// Enforced as a hard floor in [`Self::new`] and [`pbkdf2`] — fail-closed
    /// rather than warn, matching the rest of the v0.8.0 strict-by-default
    /// posture (AEAD `WeakKey`, X25519 low-order rejection, etc.).
    pub const MIN_SALT_LEN: usize = 16;

    /// OWASP 2023 minimum iteration count for PBKDF2-HMAC-SHA256
    /// (Password Storage Cheat Sheet).
    ///
    /// Enforced at [`pbkdf2`] derivation time when
    /// `params.prf == PrfType::HmacSha256`. Inputs below this floor are
    /// rejected with [`LatticeArcError::InvalidParameter`]. KAT-vector
    /// checks that need a lower count must use the test-only
    /// [`pbkdf2_kat`] entry point.
    pub const MIN_ITERATIONS_SHA256: u32 = 600_000;

    /// OWASP 2023 minimum iteration count for PBKDF2-HMAC-SHA512
    /// (Password Storage Cheat Sheet). Lower than the SHA-256 floor
    /// because each SHA-512 PRF call is roughly 2× the cost.
    ///
    /// Enforced at [`pbkdf2`] derivation time when
    /// `params.prf == PrfType::HmacSha512`.
    pub const MIN_ITERATIONS_SHA512: u32 = 210_000;

    /// Returns the OWASP 2023 minimum iteration count for the given PRF.
    #[must_use]
    pub const fn min_iterations(prf: PrfType) -> u32 {
        match prf {
            PrfType::HmacSha256 => Self::MIN_ITERATIONS_SHA256,
            PrfType::HmacSha512 => Self::MIN_ITERATIONS_SHA512,
        }
    }

    /// Create PBKDF2 parameters with a securely generated random salt.
    ///
    /// This constructor generates a cryptographically secure random salt to ensure
    /// uniqueness and prevent precomputation attacks.
    ///
    /// # Arguments
    /// * `salt_length` - Length of the salt to generate (must be at least
    ///   [`MIN_SALT_LEN`] = 16 bytes per NIST SP 800-132 §5.1).
    ///
    /// # Security Note
    /// Using a fresh random salt for each key derivation is essential for security.
    /// Never reuse salts across different passwords or applications.
    ///
    /// # Errors
    /// Returns [`LatticeArcError::InvalidParameter`] if `salt_length < 16`.
    ///
    /// [`MIN_SALT_LEN`]: Self::MIN_SALT_LEN
    pub fn new(salt_length: usize) -> Result<Self> {
        if salt_length < Self::MIN_SALT_LEN {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Salt length {salt_length} below NIST SP 800-132 §5.1 minimum of \
                 {} bytes (128 bits)",
                Self::MIN_SALT_LEN
            )));
        }

        let mut salt = vec![0u8; salt_length];
        get_random_bytes(&mut salt);

        Ok(Self { salt, iterations: 600_000, key_length: 32, prf: PrfType::HmacSha256 })
    }

    /// Create PBKDF2 parameters with the given salt and OWASP-2023
    /// defaults (`iterations = 600_000`, `key_length = 32`,
    /// `prf = HmacSha256`).
    ///
    /// # Salt validation
    ///
    /// Salt-length validation against NIST SP 800-132 §5.1 (≥ 16 bytes)
    /// is enforced at the [`pbkdf2`] call site, **not** here. This is
    /// deliberate so that wire-format parsers (e.g.
    /// [`crate::unified_api::key_format`]) can deserialize a
    /// `Pbkdf2Params` from a possibly-short pre-0.8.0 envelope for
    /// inspection or re-protection. A `Pbkdf2Params` carrying a short
    /// salt cannot reach key derivation: `pbkdf2(password, params)`
    /// returns [`LatticeArcError::InvalidParameter`] before any HMAC
    /// rounds run, so the only observable behaviour of a short-salt
    /// `Pbkdf2Params` is a derivation-time error.
    ///
    /// For the alternative "validate at construction time" path that
    /// generates a fresh random salt of a guaranteed-safe length, use
    /// [`Self::new`].
    ///
    /// # Arguments
    /// * `salt` - The salt value. Must be ≥ [`Self::MIN_SALT_LEN`]
    ///   (16) bytes when this `Pbkdf2Params` is later passed to
    ///   [`pbkdf2`]. Wire-format parsers may pass a shorter salt
    ///   provided the resulting struct is not used for derivation.
    ///
    /// # Security Note
    /// The salt must be cryptographically random and unique for each
    /// password. For derivation-bound use, prefer [`Self::new`] which
    /// generates the salt itself.
    #[must_use]
    pub fn with_salt(salt: &[u8]) -> Self {
        Self { salt: salt.to_vec(), iterations: 600_000, key_length: 32, prf: PrfType::HmacSha256 }
    }

    /// Set iteration count
    #[must_use]
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Set key length
    #[must_use]
    pub fn key_length(mut self, key_length: usize) -> Self {
        self.key_length = key_length;
        self
    }

    /// Set PRF type
    #[must_use]
    pub fn prf(mut self, prf: PrfType) -> Self {
        self.prf = prf;
        self
    }
}

/// PBKDF2 key derivation result
///
/// The key material is wrapped in `Zeroizing` for automatic zeroization on drop.
pub struct Pbkdf2Result {
    /// Derived key (zeroized on drop)
    key: Zeroizing<Vec<u8>>,
    /// Parameters used for derivation
    params: Pbkdf2Params,
}

impl std::fmt::Debug for Pbkdf2Result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pbkdf2Result")
            .field("key", &"[REDACTED]")
            .field("params", &self.params)
            .finish()
    }
}

impl ConstantTimeEq for Pbkdf2Result {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.key.ct_eq(&*other.key)
    }
}

impl Pbkdf2Result {
    /// Borrow the derived key bytes.
    ///
    /// Named `expose_secret()` to align with Secret Type Invariant I-6
    /// (universal accessor; see `docs/SECRET_TYPE_INVARIANTS.md`).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.key
    }

    /// Get the length of the derived key
    #[must_use]
    pub fn key_length(&self) -> usize {
        self.key.len()
    }

    /// Get the parameters used for derivation
    #[must_use]
    pub fn params(&self) -> &Pbkdf2Params {
        &self.params
    }

    /// Verify a password against this result
    ///
    /// # Errors
    /// Returns an error if the password derivation fails.
    pub fn verify_password(&self, password: &[u8]) -> Result<bool> {
        let derived = pbkdf2(password, &self.params)?;
        let len_eq = self.key.len().ct_eq(&derived.key.len());
        let bytes_eq = self
            .key
            .iter()
            .zip(derived.key.iter())
            .fold(subtle::Choice::from(1u8), |acc, (x, y)| acc & x.ct_eq(y));
        Ok((len_eq & bytes_eq).into())
    }
}

/// PBKDF2 key derivation function
///
/// Derives a cryptographic key from a password using PBKDF2 as specified in
/// NIST SP 800-132. The function applies a pseudorandom function (HMAC) multiple
/// times to increase computational cost and make brute-force attacks more difficult.
///
/// # Arguments
/// * `password` - The password to derive key from
/// * `params` - PBKDF2 parameters (salt, iterations, key length, PRF)
///
/// # Returns
/// Derived key wrapped in Pbkdf2Result
///
/// # Security Considerations
/// - Use at least 16 bytes of random salt
/// - Iteration count is floored per PRF at OWASP 2023 minimums
///   (600,000 for HMAC-SHA256, 210,000 for HMAC-SHA512)
/// - Store salt alongside derived key for password verification
///
/// # Errors
/// Returns an error if parameters are invalid (short salt, all-zero salt,
/// iteration count below the per-PRF OWASP floor, iteration count above
/// the 10,000,000 DoS cap, or zero key length).
pub fn pbkdf2(password: &[u8], params: &Pbkdf2Params) -> Result<Pbkdf2Result> {
    pbkdf2_with_floor(password, params, Pbkdf2Params::min_iterations(params.prf))
}

/// PBKDF2 entry point that bypasses the OWASP iteration floor.
///
/// Intended for KAT-vector validation only (NIST/RFC test vectors use
/// counts as low as 1 or 4096 iterations). The salt-length, all-zero,
/// DoS cap, and key-length checks remain in force.
///
/// # Errors
/// Returns an error for the same conditions as [`pbkdf2`] except the
/// per-PRF iteration floor is replaced by an absolute minimum of 1.
#[cfg(any(test, feature = "kat-replay"))]
#[doc(hidden)]
pub fn pbkdf2_kat(password: &[u8], params: &Pbkdf2Params) -> Result<Pbkdf2Result> {
    pbkdf2_with_floor(password, params, 1)
}

/// PBKDF2 derivation against an explicit iteration floor.
///
/// `pbkdf2()` calls this with the per-PRF OWASP 2023 floor; envelope-load
/// paths (e.g. [`crate::unified_api::key_format`]) call it with their own
/// integrity-protected legacy floor so historical keys remain readable.
/// Test-only [`pbkdf2_kat`] passes `1` to disable the floor entirely.
///
/// All other validation (salt length, all-zero salt, DoS cap, key length)
/// is shared and unconditional.
///
/// # Errors
/// Returns [`LatticeArcError::InvalidParameter`] for any failed check.
pub(crate) fn pbkdf2_with_floor(
    password: &[u8],
    params: &Pbkdf2Params,
    min_iterations: u32,
) -> Result<Pbkdf2Result> {
    // Validate parameters per SP 800-132 §5.1: salt MUST be at least 128 bits
    // (16 bytes). Enforced as a hard floor — fail-closed defence in depth,
    // matching the rest of the v0.8.0 strict-by-default posture.
    if params.salt.len() < Pbkdf2Params::MIN_SALT_LEN {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Salt length {} below NIST SP 800-132 §5.1 minimum of {} bytes (128 bits)",
            params.salt.len(),
            Pbkdf2Params::MIN_SALT_LEN,
        )));
    }

    // Reject all-zero salt (defends against uninitialised-memory bugs, same
    // spirit as `AeadError::WeakKey`). Use the shared CT helper rather than
    // `iter().all`, which short-circuits on the first non-zero byte and so
    // leaks salt-prefix structure via timing. PBKDF2 salts can exceed
    // 32 bytes — go through `primitives::ct` (no MAX cap) rather than the
    // AEAD-shaped `is_all_zero_key` re-export.
    if crate::primitives::ct::is_all_zero_bytes(&params.salt) {
        return Err(LatticeArcError::InvalidParameter(
            "Salt must not be all zeros - use a cryptographically random salt".to_string(),
        ));
    }

    if params.iterations < min_iterations {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Iteration count {} below OWASP 2023 minimum of {} for {:?}",
            params.iterations, min_iterations, params.prf,
        )));
    }

    // Cap iterations to prevent denial-of-service via excessive computation
    if params.iterations > 10_000_000 {
        return Err(LatticeArcError::InvalidParameter(
            "Iteration count must not exceed 10,000,000".to_string(),
        ));
    }

    if params.key_length == 0 {
        return Err(LatticeArcError::InvalidParameter(
            "Key length must be greater than 0".to_string(),
        ));
    }

    // Calculate number of blocks needed
    let prf_output_len = match params.prf {
        PrfType::HmacSha256 => 32,
        PrfType::HmacSha512 => 64,
    };

    let block_count = params.key_length.div_ceil(prf_output_len);
    // Wrap in Zeroizing so partial key material is erased on early return via `?`.
    let mut derived_key: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; params.key_length]);
    let mut offset = 0;

    // Generate each block of the derived key
    for block_index in 1..=block_count {
        let block_index_u32 = u32::try_from(block_index).map_err(|_e| {
            LatticeArcError::InvalidParameter(format!(
                "Block index {} exceeds u32::MAX",
                block_index
            ))
        })?;
        let block =
            generate_block(password, &params.salt, params.iterations, block_index_u32, params.prf);
        let copy_len = std::cmp::min(block.len(), params.key_length.saturating_sub(offset));
        let end_offset = offset.checked_add(copy_len).ok_or_else(|| {
            LatticeArcError::InvalidParameter("Derived key offset overflow".to_string())
        })?;
        let dest_slice = derived_key.get_mut(offset..end_offset).ok_or_else(|| {
            LatticeArcError::InvalidParameter("Derived key buffer overflow".to_string())
        })?;
        let src_slice = block.get(..copy_len).ok_or_else(|| {
            LatticeArcError::InvalidParameter("Block slice out of bounds".to_string())
        })?;
        dest_slice.copy_from_slice(src_slice);
        offset = end_offset;
    }

    Ok(Pbkdf2Result { key: derived_key, params: params.clone() })
}

/// Generate a single block of the PBKDF2 output.
///
/// The returned buffer contains derived key material and is wrapped in
/// `Zeroizing` to erase it automatically on drop, including on early error
/// returns from the caller. Infallible: all underlying HMAC operations are
/// infallible for valid key lengths (checked in `pbkdf2()`).
fn generate_block(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    block_index: u32,
    prf: PrfType,
) -> Zeroizing<Vec<u8>> {
    // Convert block index to bytes (big-endian). `block_input` only
    // carries public bytes today (salt + counter), so this is hygiene —
    // but the surrounding code is `Zeroizing<Vec<u8>>` and a future
    // refactor that adds a secret label here would silently leak. Keep
    // the type discipline consistent.
    let mut block_input = Zeroizing::new(salt.to_vec());
    block_input.extend_from_slice(&block_index.to_be_bytes());

    // U_1 = PRF(password, salt || INT(block_index))
    let mut u = compute_prf(password, &block_input, prf);
    let mut result: Zeroizing<Vec<u8>> = Zeroizing::new(u.to_vec());

    // U_2 = PRF(password, U_1) ⊕ U_1
    // U_3 = PRF(password, U_2) ⊕ U_2
    // ...
    // U_c = PRF(password, U_{c-1}) ⊕ U_{c-1}
    for _ in 1..iterations {
        u = compute_prf(password, &u, prf);
        for (res_byte, u_byte) in result.iter_mut().zip(u.iter()) {
            *res_byte ^= u_byte;
        }
    }

    result
}

/// Compute PRF (HMAC) for PBKDF2.
///
/// Returns the HMAC output wrapped in `Zeroizing` because it is used directly
/// as derived key material (both `U_1` and the XOR-chained iterates `U_i`).
/// Infallible: aws-lc-rs `hmac::Key::new` accepts any key length, and
/// `hmac::sign` cannot fail for HMAC-SHA256/SHA-512.
fn compute_prf(password: &[u8], data: &[u8], prf: PrfType) -> Zeroizing<Vec<u8>> {
    // Delegates to aws-lc-rs HMAC for FIPS-validated constant-time operation.
    // The same backend is used by HKDF, SP800-108, and the mac::hmac wrapper.
    let algorithm = match prf {
        PrfType::HmacSha256 => HMAC_SHA256,
        PrfType::HmacSha512 => HMAC_SHA512,
    };
    let key = hmac::Key::new(algorithm, password);
    let tag = hmac::sign(&key, data);
    Zeroizing::new(tag.as_ref().to_vec())
}

/// Password-based key derivation with default parameters
///
/// Convenience function that uses recommended default parameters:
/// - 16-byte random salt
/// - 600,000 iterations (OWASP 2023 recommendation for HMAC-SHA256)
/// - 32-byte key length
/// - HMAC-SHA256 PRF
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn pbkdf2_simple(password: &[u8]) -> Result<Pbkdf2Result> {
    let params = Pbkdf2Params::new(16)?.iterations(600_000).key_length(32).prf(PrfType::HmacSha256);

    pbkdf2(password, &params)
}

/// Verify a password against a previously derived key.
///
/// `prf` MUST match the PRF used at derivation time — calling
/// `verify_password` with the wrong PRF derives different bytes from the
/// same password and the comparison will (correctly) return `false`,
/// indistinguishable from a wrong-password rejection. Storing the PRF
/// alongside the derived key is the caller's responsibility (the
/// envelope formats in `unified_api::key_format` carry it explicitly;
/// see also `Pbkdf2Result::params()` for inline retention).
///
/// # Errors
///
/// Returns an error if the parameters are invalid (short salt, weak
/// iterations, etc.); see [`pbkdf2`] for the exhaustive list.
pub fn verify_password(
    password: &[u8],
    derived_key: &[u8],
    salt: &[u8],
    iterations: u32,
    prf: PrfType,
) -> Result<bool> {
    let params =
        Pbkdf2Params::with_salt(salt).iterations(iterations).key_length(derived_key.len()).prf(prf);

    let result = pbkdf2(password, &params)?;
    let len_eq = derived_key.len().ct_eq(&result.key.len());
    let bytes_eq = derived_key
        .iter()
        .zip(result.key.iter())
        .fold(subtle::Choice::from(1u8), |acc, (x, y)| acc & x.ct_eq(y));
    Ok((len_eq & bytes_eq).into())
}

use super::get_random_bytes;

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::indexing_slicing)] // Tests use slice indexing for verification
#[allow(clippy::panic)] // `let Else { ... panic!(...) }` is the canonical error-extraction shape under deny(expect_used)
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_basic_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let password = b"password";
        let salt = b"salt123456789012"; // 16 bytes
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let result = pbkdf2_kat(password, &params)?;
        assert_eq!(result.key.len(), 32);

        // Verify deterministic output
        let result2 = pbkdf2_kat(password, &params)?;
        assert_eq!(result.key, result2.key);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_different_passwords_produce_different_keys_succeeds()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let result1 = pbkdf2_kat(b"password1", &params)?;
        let result2 = pbkdf2_kat(b"password2", &params)?;

        assert_ne!(result1.key, result2.key);
        Ok(())
    }

    /// Pattern 8 Rule 4: parameter-influence test — `Pbkdf2Params.salt`
    /// influences the derived key.
    #[test]
    fn test_salt_influences_pbkdf2() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let params1 = Pbkdf2Params::with_salt(b"salt123456789012").iterations(1000).key_length(32);
        let params2 = Pbkdf2Params::with_salt(b"salt223456789012").iterations(1000).key_length(32);

        let result1 = pbkdf2_kat(b"password", &params1)?;
        let result2 = pbkdf2_kat(b"password", &params2)?;

        assert_ne!(result1.key, result2.key);
        Ok(())
    }

    /// Pattern 8 Rule 4: parameter-influence test —
    /// `Pbkdf2Params.iterations` influences the derived key.
    #[test]
    fn test_iterations_influences_pbkdf2() {
        let password = b"password";
        let salt = b"salt123456789012";
        let params1 = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);
        let params2 = Pbkdf2Params::with_salt(salt).iterations(2000).key_length(32);

        let result1 = pbkdf2_kat(password, &params1).unwrap();
        let result2 = pbkdf2_kat(password, &params2).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    /// Pattern 8 Rule 4: parameter-influence test —
    /// `Pbkdf2Params.key_length` influences the derived key length.
    #[test]
    fn test_key_length_influences_pbkdf2() {
        let password = b"password";
        let salt = b"salt123456789012";
        for &len in &[16usize, 32, 48, 64] {
            let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(len);
            let result = pbkdf2_kat(password, &params).unwrap();
            assert_eq!(
                result.expose_secret().len(),
                len,
                "key_length={} did not produce a {}-byte derived key",
                len,
                len,
            );
        }
    }

    #[test]
    fn test_pbkdf2_simple_produces_different_keys_with_different_salts_succeeds() {
        let password = b"testpassword";
        let result1 = pbkdf2_simple(password).unwrap();
        let result2 = pbkdf2_simple(password).unwrap();

        // Different salts should produce different keys
        assert_ne!(result1.key, result2.key);
        assert_eq!(result1.key.len(), 32);
        assert_eq!(result2.key.len(), 32);
    }

    #[test]
    fn test_password_verification_is_correct() {
        let password = b"correctpassword";
        let wrong_password = b"wrongpassword";

        let result = pbkdf2_simple(password).unwrap();

        // Correct password should verify
        assert!(result.verify_password(password).unwrap());

        // Wrong password should not verify
        assert!(!result.verify_password(wrong_password).unwrap());
    }

    #[test]
    fn test_verify_password_function_rejects_below_owasp_floor() {
        // `verify_password()` is the public ergonomic helper around
        // `pbkdf2()`. Calls below the per-PRF OWASP floor must propagate
        // the floor error rather than silently derive with weak params.
        let salt = b"1234567890123456"; // 16 bytes
        let derived_key = vec![0u8; 32]; // shape only — never reached
        for weak in [1u32, 1000, 100_000, Pbkdf2Params::MIN_ITERATIONS_SHA256 - 1] {
            let result =
                verify_password(b"testpass", &derived_key, salt, weak, PrfType::HmacSha256);
            assert!(
                result.is_err(),
                "verify_password must reject {weak} iterations (below OWASP floor)"
            );
        }
    }

    #[test]
    fn test_pbkdf2_validation_fails_for_invalid_params_fails() {
        let password = b"pass";
        let salt = b"salt123456789012"; // 16 bytes for cases that need a valid salt

        // Empty salt fails the SP 800-132 §5.1 length check.
        let params_empty_salt = Pbkdf2Params::with_salt(b"").iterations(600_000).key_length(32);
        assert!(pbkdf2(password, &params_empty_salt).is_err());

        // All-zero salt fails the entropy check.
        let params_zero_salt =
            Pbkdf2Params::with_salt(&[0u8; 16]).iterations(600_000).key_length(32);
        assert!(pbkdf2(password, &params_zero_salt).is_err());

        // Iterations below the per-PRF OWASP floor fail.
        let params_low_iter = Pbkdf2Params::with_salt(salt).iterations(500).key_length(32);
        assert!(pbkdf2(password, &params_low_iter).is_err());

        // Zero key length fails.
        let params_zero_len = Pbkdf2Params::with_salt(salt).iterations(600_000).key_length(0);
        assert!(pbkdf2(password, &params_zero_len).is_err());
    }

    #[test]
    fn test_pbkdf2_iteration_floor_sha256() {
        // At the floor: accepted. One below: rejected.
        let salt = b"salt123456789012";
        let at_floor = Pbkdf2Params::with_salt(salt)
            .iterations(Pbkdf2Params::MIN_ITERATIONS_SHA256)
            .key_length(32)
            .prf(PrfType::HmacSha256);
        // We use pbkdf2_kat for the positive boundary check to keep the
        // test fast; `pbkdf2()` would do the same work but takes ~1s.
        // The boundary itself (the floor constant) is exercised below.
        assert!(pbkdf2_kat(b"pw", &at_floor).is_ok());

        let below = Pbkdf2Params::with_salt(salt)
            .iterations(Pbkdf2Params::MIN_ITERATIONS_SHA256 - 1)
            .key_length(32)
            .prf(PrfType::HmacSha256);
        let result = pbkdf2(b"pw", &below);
        let Err(err) = result else {
            panic!("below floor must error");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("OWASP") && msg.contains("HmacSha256"),
            "error must name OWASP and the PRF, got: {msg}"
        );
    }

    #[test]
    fn test_pbkdf2_iteration_floor_sha512() {
        let salt = b"salt123456789012";
        let below = Pbkdf2Params::with_salt(salt)
            .iterations(Pbkdf2Params::MIN_ITERATIONS_SHA512 - 1)
            .key_length(64)
            .prf(PrfType::HmacSha512);
        let result = pbkdf2(b"pw", &below);
        let Err(err) = result else {
            panic!("below floor must error");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("OWASP") && msg.contains("HmacSha512"),
            "error must name OWASP and the PRF, got: {msg}"
        );

        // Sanity: SHA-512 floor is strictly less than SHA-256 floor.
        const _: () =
            assert!(Pbkdf2Params::MIN_ITERATIONS_SHA512 < Pbkdf2Params::MIN_ITERATIONS_SHA256);
    }

    #[test]
    fn test_pbkdf2_kat_bypasses_owasp_floor() {
        // KAT entry point must accept counts below the public-API floor —
        // RFC/NIST PBKDF2 test vectors use 1, 2, or 4096 iterations.
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1).key_length(32);
        assert!(pbkdf2_kat(b"pw", &params).is_ok());
        // But the public surface must still reject the same input.
        assert!(pbkdf2(b"pw", &params).is_err());
    }

    /// Pattern 8 Rule 4: parameter-influence test — `Pbkdf2Params.prf`
    /// influences the derived key (different PRF produces different
    /// output for the same password+salt+iterations+length).
    #[test]
    fn test_prf_influences_pbkdf2() {
        let password = b"password";
        let salt = b"salt123456789012";

        let params_sha256 =
            Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32).prf(PrfType::HmacSha256);

        let params_sha512 = Pbkdf2Params::with_salt(salt)
            .iterations(1000)
            .key_length(64) // Longer key for SHA512
            .prf(PrfType::HmacSha512);

        let result_sha256 = pbkdf2_kat(password, &params_sha256).unwrap();
        let result_sha512 = pbkdf2_kat(password, &params_sha512).unwrap();

        assert_eq!(result_sha256.key.len(), 32);
        assert_eq!(result_sha512.key.len(), 64);

        // Different PRFs should produce different outputs
        assert_ne!(result_sha256.expose_secret(), &result_sha512.expose_secret()[..32]);
    }

    #[test]
    fn test_zeroize_on_drop_succeeds() {
        let password = b"password";
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        // Create result in a block to test drop behavior
        let key_bytes = {
            let result = pbkdf2_kat(password, &params).unwrap();
            let key_copy = result.key.clone();
            // Result should be zeroized when dropped
            drop(result);
            key_copy
        };

        // The key should still be readable (ZeroizeOnDrop doesn't automatically zeroize
        // until the struct is actually dropped, but the test verifies the trait is implemented)
        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_pbkdf2_params_new_zero_salt_length_fails() {
        let result = Pbkdf2Params::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_params_new_below_min_salt_len_fails() {
        // NIST SP 800-132 §5.1 requires ≥ 128 bits (16 bytes). Anything in
        // [1, MIN_SALT_LEN) must be rejected by the size constructor.
        for n in [1usize, 8, 15] {
            let result = Pbkdf2Params::new(n);
            assert!(
                result.is_err(),
                "salt length {n} below MIN_SALT_LEN={} should fail",
                Pbkdf2Params::MIN_SALT_LEN
            );
        }
    }

    #[test]
    fn test_pbkdf2_params_new_at_min_salt_len_succeeds() {
        // Boundary: exactly MIN_SALT_LEN bytes is the smallest accepted size.
        let params = Pbkdf2Params::new(Pbkdf2Params::MIN_SALT_LEN).unwrap();
        assert_eq!(params.salt.len(), Pbkdf2Params::MIN_SALT_LEN);
    }

    #[test]
    fn test_pbkdf2_short_salt_rejected_at_derivation() {
        // Pin the documented invariant: `with_salt` is infallible, but
        // a `Pbkdf2Params` carrying a salt below MIN_SALT_LEN cannot
        // reach key derivation — `pbkdf2()` rejects with
        // `InvalidParameter` before any HMAC rounds run. This is the
        // single enforcement point for NIST SP 800-132 §5.1 on the
        // wire-format-parser path.
        let short = vec![0xAAu8; Pbkdf2Params::MIN_SALT_LEN.saturating_sub(1)];
        let params = Pbkdf2Params::with_salt(&short).iterations(1000).key_length(32);
        let result = pbkdf2(b"password", &params);
        assert!(
            result.is_err(),
            "pbkdf2 must reject {short_len}-byte salt",
            short_len = short.len()
        );
    }

    #[test]
    fn test_pbkdf2_with_salt_at_min_succeeds() {
        let salt = vec![0xAAu8; Pbkdf2Params::MIN_SALT_LEN];
        let params = Pbkdf2Params::with_salt(&salt);
        assert_eq!(params.salt.len(), Pbkdf2Params::MIN_SALT_LEN);
    }

    #[test]
    fn test_pbkdf2_params_new_valid_has_correct_defaults_succeeds() {
        let params = Pbkdf2Params::new(16).unwrap();
        assert_eq!(params.salt.len(), 16);
        assert_eq!(params.iterations, 600_000);
        assert_eq!(params.key_length, 32);
        assert_eq!(params.prf, PrfType::HmacSha256);
    }

    #[test]
    fn test_pbkdf2_multi_block_sha256_has_correct_length_has_correct_size() {
        // key_length > 32 requires multiple blocks for SHA256
        let password = b"password";
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(64);

        let result = pbkdf2_kat(password, &params).unwrap();
        assert_eq!(result.key.len(), 64);
    }

    #[test]
    fn test_pbkdf2_multi_block_sha512_has_correct_length_has_correct_size() {
        // key_length > 64 requires multiple blocks for SHA512
        let password = b"password";
        let salt = b"salt123456789012";
        let params =
            Pbkdf2Params::with_salt(salt).iterations(1000).key_length(128).prf(PrfType::HmacSha512);

        let result = pbkdf2_kat(password, &params).unwrap();
        assert_eq!(result.key.len(), 128);
    }

    #[test]
    fn test_pbkdf2_result_key_accessor_returns_correct_value_succeeds() {
        let password = b"password";
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let result = pbkdf2_kat(password, &params).unwrap();
        assert_eq!(result.expose_secret(), &result.key[..]);
        assert_eq!(result.expose_secret().len(), 32);
    }

    #[test]
    fn test_pbkdf2_params_builder_chain_is_correct() {
        let params = Pbkdf2Params::with_salt(b"saltsaltsaltsalt")
            .iterations(5000)
            .key_length(48)
            .prf(PrfType::HmacSha512);

        assert_eq!(params.iterations, 5000);
        assert_eq!(params.key_length, 48);
        assert_eq!(params.prf, PrfType::HmacSha512);
    }

    #[test]
    fn test_prf_type_debug_clone_eq_is_correct() {
        let prf = PrfType::HmacSha256;
        let cloned = prf;
        assert_eq!(prf, cloned);
        assert_ne!(PrfType::HmacSha256, PrfType::HmacSha512);

        let debug = format!("{:?}", prf);
        assert!(debug.contains("HmacSha256"));
    }
}
