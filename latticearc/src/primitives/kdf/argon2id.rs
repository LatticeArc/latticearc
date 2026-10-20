#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! RFC 9106: Argon2id memory-hard password-based key derivation
//!
//! Argon2id derives a key from a password and a salt while forcing every
//! guess to fill and revisit a configurable amount of memory. It is the
//! variant RFC 9106 §4 recommends when the deployment does not know which
//! Argon2 type to pick.
//!
//! This module wraps the RustCrypto `argon2` crate (raw-hash API only, no PHC
//! string format) with:
//! - Parameter validation against RFC 9106 §3.1 plus library floors
//!   ([`Argon2Params::validate`])
//! - A memory cap enforced through
//!   [`ResourceLimits::max_argon2_memory_kib`](crate::primitives::resource_limits::ResourceLimits)
//!   before any allocation
//! - Zeroized working memory and output ([`Argon2idResult`])
//! - Machine-local cost calibration ([`Argon2Params::calibrate`])
//!
//! # Threat model
//!
//! - **Offline guessing.** An attacker who obtains the salt, the parameters
//!   and anything derived from the key (a ciphertext, a verifier) can test
//!   password guesses offline. Argon2id does not stop this; it makes each
//!   guess cost `memory_kib` KiB of memory for the full duration of
//!   `iterations` passes. Low-entropy passwords remain guessable; the
//!   parameters set the price per guess.
//! - **Memory hardness.** Fast hashes such as PBKDF2 parallelise cheaply on
//!   GPUs and ASICs because each guess needs almost no memory. Argon2id
//!   binds cost to memory bandwidth and capacity, where attacker hardware has
//!   far less advantage. RFC 9106 §7.2 bounds the best known time-memory
//!   trade-off against multi-pass Argon2id to a factor of about 1.33.
//! - **Salt length.** The salt makes precomputed tables useless and forces
//!   the attacker to attack each password record separately. RFC 9106 §3.1
//!   recommends 16 bytes; §4 step 7 allows 64 bits (8 bytes) where space is
//!   short. This module rejects salts shorter than 8 bytes and rejects
//!   all-zero salts, which indicate uninitialised buffers.
//! - **Side channels.** Argon2d indexes memory by password-dependent values,
//!   which leaks through cache timing to a co-located attacker. Argon2i uses
//!   data-independent indexing but is weaker against trade-off attacks.
//!   Argon2id runs the first half of the first pass data-independently and
//!   the rest data-dependently, so a cache-timing observer learns less than
//!   with Argon2d while trade-off resistance stays close to Argon2d. It is
//!   not fully constant-time: an attacker who can observe memory access
//!   patterns during the data-dependent phase still learns something.
//! - **Denial of service.** Argon2 parameters often come from stored or
//!   deserialized records. The memory cap, the iteration cap and the output
//!   length cap bound the work any single call can be made to do.
//!
//! # Not exposed
//!
//! RFC 9106 also defines an optional secret value `K` and associated data
//! `X`. The public API exposes neither: Argon2id takes no domain-separation
//! context in this library. The crate-internal path that feeds them is used
//! only to replay the RFC 9106 §5.3 test vector. The underlying crate caps
//! associated data at 32 bytes, while the RFC allows up to `2^32 - 1`.
//!
//! # FIPS 140-3
//!
//! Argon2id is not a NIST-approved KDF. Like BLAKE2, it stays compiled under
//! the `fips` feature so callers can reach it explicitly, but no policy-engine
//! path selects it. Deployments that must stay in an approved mode should use
//! [`pbkdf2`](super::pbkdf2::pbkdf2).
//!
//! # Lanes
//!
//! This build does not enable the `argon2` crate's `parallel` feature, so
//! lanes (`parallelism`) are computed one after another on a single thread.
//! `parallelism` still changes the output, as RFC 9106 requires.

use std::time::{Duration, Instant};

use crate::prelude::error::{LatticeArcError, Result};
use crate::primitives::resource_limits::{
    ResourceError, ResourceLimitsManager, get_global_resource_limits,
};
use crate::types::SecretVec;
use subtle::ConstantTimeEq;
use tracing::instrument;
use zeroize::Zeroizing;

/// Argon2id cost parameters.
///
/// The parameters are public protocol data (they are stored next to the
/// salt), so this type derives `Debug`, `Clone` and `PartialEq`.
///
/// Fields are public for wire-format parsers; [`argon2id`] validates them on
/// every call, so a struct built by hand cannot bypass the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost `m` in KiB. Must be at least `8 * parallelism` (RFC 9106
    /// §3.1) and at most the [`max_argon2_memory_kib`][cap] resource limit.
    ///
    /// Consumer: argon2id()
    ///
    /// [cap]: crate::primitives::resource_limits::ResourceLimits::max_argon2_memory_kib
    pub memory_kib: u32,
    /// Number of passes `t` over memory. Between
    /// [`Argon2Params::MIN_ITERATIONS`] and [`Argon2Params::MAX_ITERATIONS`].
    ///
    /// Consumer: argon2id()
    pub iterations: u32,
    /// Degree of parallelism `p` (number of lanes). Between
    /// [`Argon2Params::MIN_PARALLELISM`] and [`Argon2Params::MAX_PARALLELISM`].
    ///
    /// Consumer: argon2id()
    pub parallelism: u32,
    /// Derived key (tag) length in bytes. Between
    /// [`Argon2Params::MIN_OUTPUT_LEN`] and [`Argon2Params::MAX_OUTPUT_LEN`].
    ///
    /// Consumer: argon2id()
    pub output_len: usize,
}

impl Argon2Params {
    /// RFC 9106 §3.1 minimum memory per lane, in KiB (`m >= 8 * p`).
    pub const MIN_MEMORY_KIB_PER_LANE: u32 = 8;

    /// RFC 9106 §3.1 minimum number of passes.
    pub const MIN_ITERATIONS: u32 = 1;

    /// Library cap on the number of passes.
    ///
    /// RFC 9106 allows up to `2^32 - 1`; its §4 profiles use one or three
    /// passes. The cap stops a stored parameter block from pinning a CPU for
    /// hours.
    pub const MAX_ITERATIONS: u32 = 1024;

    /// RFC 9106 §3.1 minimum degree of parallelism.
    pub const MIN_PARALLELISM: u32 = 1;

    /// RFC 9106 §3.1 maximum degree of parallelism (`2^24 - 1`).
    pub const MAX_PARALLELISM: u32 = 0x00FF_FFFF;

    /// Library floor on the derived key length: 16 bytes (128 bits).
    ///
    /// RFC 9106 §3.1 permits tags as short as 4 bytes, but §4 step 8 names
    /// 128 bits as the length that suffices for key derivation. Shorter keys
    /// are rejected.
    pub const MIN_OUTPUT_LEN: usize = 16;

    /// Library cap on the derived key length: 1024 bytes.
    ///
    /// Bounds the output allocation for parameters read from untrusted
    /// records. Callers needing more key material should expand the output
    /// with HKDF.
    pub const MAX_OUTPUT_LEN: usize = 1024;

    /// Minimum salt length in bytes (RFC 9106 §4 step 7: 64 bits).
    pub const MIN_SALT_LEN: usize = 8;

    /// Recommended salt length in bytes (RFC 9106 §3.1: 16 bytes).
    pub const RECOMMENDED_SALT_LEN: usize = 16;

    /// Upper bound on the calibration target, in milliseconds (60 s).
    pub const MAX_CALIBRATION_TARGET_MS: u64 = 60_000;

    /// Memory cost of the first calibration run, in KiB (1 MiB), or the
    /// memory cap if that is smaller.
    pub const CALIBRATION_START_MEMORY_KIB: u32 = 1024;

    /// Create validated Argon2id parameters.
    ///
    /// # Errors
    /// Returns [`LatticeArcError::InvalidParameter`] if any value is outside
    /// the bounds listed in [`Self::validate`].
    pub fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        output_len: usize,
    ) -> Result<Self> {
        let params = Self { memory_kib, iterations, parallelism, output_len };
        params.validate()?;
        Ok(params)
    }

    /// Check the parameters against RFC 9106 §3.1 and the library bounds.
    ///
    /// Checks, in order:
    /// - `parallelism` in [`Self::MIN_PARALLELISM`]..=[`Self::MAX_PARALLELISM`]
    /// - `memory_kib >= 8 * parallelism`
    /// - `iterations` in [`Self::MIN_ITERATIONS`]..=[`Self::MAX_ITERATIONS`]
    /// - `output_len` in [`Self::MIN_OUTPUT_LEN`]..=[`Self::MAX_OUTPUT_LEN`]
    ///
    /// The memory cap from resource limits is checked separately by
    /// [`argon2id`], because it can change at runtime.
    ///
    /// # Errors
    /// Returns [`LatticeArcError::InvalidParameter`] naming the first failed
    /// check.
    pub fn validate(&self) -> Result<()> {
        let Self { memory_kib, iterations, parallelism, output_len } = *self;
        if !(Self::MIN_PARALLELISM..=Self::MAX_PARALLELISM).contains(&parallelism) {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Argon2id parallelism {parallelism} outside RFC 9106 range {}..={}",
                Self::MIN_PARALLELISM,
                Self::MAX_PARALLELISM
            )));
        }
        // `parallelism <= 2^24 - 1`, so `8 * parallelism` fits in u32; the
        // saturating form keeps the arithmetic lint-clean.
        let min_memory = parallelism.saturating_mul(Self::MIN_MEMORY_KIB_PER_LANE);
        if memory_kib < min_memory {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Argon2id memory {memory_kib} KiB below RFC 9106 minimum of 8 * parallelism \
                 = {min_memory} KiB"
            )));
        }
        if !(Self::MIN_ITERATIONS..=Self::MAX_ITERATIONS).contains(&iterations) {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Argon2id iterations {iterations} outside allowed range {}..={}",
                Self::MIN_ITERATIONS,
                Self::MAX_ITERATIONS
            )));
        }
        if !(Self::MIN_OUTPUT_LEN..=Self::MAX_OUTPUT_LEN).contains(&output_len) {
            return Err(LatticeArcError::InvalidParameter(format!(
                "Argon2id output length {output_len} outside allowed range {}..={} bytes",
                Self::MIN_OUTPUT_LEN,
                Self::MAX_OUTPUT_LEN
            )));
        }
        Ok(())
    }

    /// Measure Argon2id on this machine and pick parameters that take about
    /// `target_ms` milliseconds per derivation.
    ///
    /// Follows the procedure in RFC 9106 §4: memory first, then passes.
    /// With `parallelism = 1` and a 32-byte output, it starts at
    /// [`Self::CALIBRATION_START_MEMORY_KIB`] and one pass, doubles the
    /// memory until it reaches the cap or a run exceeds the target, and then
    /// sets the pass count from the measured one-pass time, rounding down so
    /// the estimate stays within the target.
    ///
    /// The memory cap is the smaller of `max_memory_kib` and the
    /// [`max_argon2_memory_kib`][cap] resource limit, so the result is always
    /// accepted by [`argon2id`] under the current limits.
    ///
    /// The result is machine- and load-dependent. Calibrate once at
    /// provisioning time and store the parameters with the salt; do not
    /// recalibrate when verifying, or the derived key changes. If even the
    /// first run exceeds the target, the first run's parameters are returned.
    ///
    /// Memory doubles geometrically and the run that overshoots costs at most
    /// about twice the target, so calibration takes roughly three times
    /// `target_ms` plus the first run.
    ///
    /// # Errors
    /// Returns [`LatticeArcError::InvalidParameter`] if `target_ms` is zero or
    /// above [`Self::MAX_CALIBRATION_TARGET_MS`], or if the effective memory
    /// cap is below [`Self::MIN_MEMORY_KIB_PER_LANE`]. Propagates any error
    /// from the measurement runs.
    ///
    /// [cap]: crate::primitives::resource_limits::ResourceLimits::max_argon2_memory_kib
    #[instrument(level = "debug")]
    pub fn calibrate(target_ms: u64, max_memory_kib: u32) -> Result<Self> {
        calibrate_with_limits(target_ms, max_memory_kib, get_global_resource_limits())
    }
}

impl Default for Argon2Params {
    /// Mobile-friendly profile: 64 MiB, 3 passes, 1 lane, 32-byte key.
    ///
    /// Memory and passes match the RFC 9106 §4 SECOND RECOMMENDED option
    /// (`t = 3`, `m = 2^16` KiB), which the RFC gives for systems with much
    /// less memory than the 2 GiB first option; 64 MiB fits phones and small
    /// containers. The RFC option uses `p = 4`; this profile uses `p = 1`
    /// because lanes run sequentially in this build (see the
    /// [module docs](self)), so extra lanes add no defender throughput. The
    /// 32-byte output is a 256-bit key. Use [`Argon2Params::calibrate`] to
    /// tune for a specific machine.
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 1, output_len: 32 }
    }
}

/// Argon2id key derivation result.
///
/// The derived key is held in a [`SecretVec`], which zeroizes on drop. `Debug`
/// redacts the key; comparison is constant-time via [`ConstantTimeEq`].
pub struct Argon2idResult {
    /// Derived key (zeroized on drop).
    key: SecretVec,
    /// Parameters used for derivation.
    params: Argon2Params,
}

impl std::fmt::Debug for Argon2idResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Argon2idResult")
            .field("key", &"[REDACTED]")
            .field("params", &self.params)
            .finish()
    }
}

impl ConstantTimeEq for Argon2idResult {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.key.ct_eq(&other.key)
    }
}

impl Argon2idResult {
    /// Borrow the derived key bytes.
    ///
    /// Named `expose_secret()` to align with Secret Type Invariant I-8
    /// (single sealed accessor; see `docs/SECRET_TYPE_INVARIANTS.md`).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.key.expose_secret()
    }

    /// Length of the derived key in bytes.
    #[must_use]
    pub fn key_length(&self) -> usize {
        self.key.len()
    }

    /// Parameters used for derivation.
    #[must_use]
    pub fn params(&self) -> &Argon2Params {
        &self.params
    }
}

/// Derive a key from a password with Argon2id (RFC 9106, version 0x13).
///
/// # Arguments
/// * `password` - Password bytes. Must not be empty.
/// * `salt` - Unique random salt, at least [`Argon2Params::MIN_SALT_LEN`]
///   (8) bytes; [`Argon2Params::RECOMMENDED_SALT_LEN`] (16) is recommended.
/// * `params` - Cost parameters; see [`Argon2Params`].
///
/// # Input policy
///
/// RFC 9106 allows an empty password. This function rejects it, matching
/// `hkdf_extract`'s rejection of empty input keying material: an empty
/// password protects nothing and usually signals a caller bug. All-zero
/// salts are rejected as a guard against uninitialised buffers, matching
/// [`pbkdf2`](super::pbkdf2::pbkdf2).
///
/// # Errors
/// - [`LatticeArcError::InvalidParameter`] for an empty password, a salt
///   shorter than 8 bytes or all zero, or parameters that fail
///   [`Argon2Params::validate`].
/// - [`LatticeArcError::ResourceExhausted`] if `params.memory_kib` exceeds
///   the `max_argon2_memory_kib` resource limit, or the working memory
///   cannot be allocated.
/// - [`LatticeArcError::InvalidConfiguration`] if the resource limits cannot
///   be read.
#[instrument(
    level = "debug",
    skip(password, salt),
    fields(password_len = password.len(), salt_len = salt.len())
)]
pub fn argon2id(password: &[u8], salt: &[u8], params: &Argon2Params) -> Result<Argon2idResult> {
    argon2id_inner(password, salt, &[], &[], params, get_global_resource_limits())
}

/// Shared Argon2id derivation path.
///
/// `secret` and `associated_data` are the optional RFC 9106 inputs `K` and
/// `X`. The public [`argon2id`] passes empty slices, which RFC 9106 §3.2
/// encodes identically to omitting them. Only the RFC 9106 §5.3 test-vector
/// replay passes non-empty values.
///
/// # Errors
/// See [`argon2id`].
pub(crate) fn argon2id_inner(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: &Argon2Params,
    limits: &ResourceLimitsManager,
) -> Result<Argon2idResult> {
    params.validate()?;
    let Argon2Params { memory_kib, iterations, parallelism, output_len } = *params;

    if password.is_empty() {
        return Err(LatticeArcError::InvalidParameter(
            "Argon2id password must not be empty".to_string(),
        ));
    }
    if salt.len() < Argon2Params::MIN_SALT_LEN {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Argon2id salt length {} below RFC 9106 minimum of {} bytes",
            salt.len(),
            Argon2Params::MIN_SALT_LEN
        )));
    }
    if crate::primitives::ct::is_all_zero_bytes(salt) {
        return Err(LatticeArcError::InvalidParameter(
            "Argon2id salt must not be all zeros - use a cryptographically random salt".to_string(),
        ));
    }

    // Memory cap: checked before any allocation.
    limits.validate_argon2_memory_kib(memory_kib).map_err(map_resource_error)?;

    let data = argon2::AssociatedData::new(associated_data).map_err(map_argon2_error)?;
    let argon2_params = argon2::ParamsBuilder::new()
        .m_cost(memory_kib)
        .t_cost(iterations)
        .p_cost(parallelism)
        .output_len(output_len)
        .data(data)
        .build()
        .map_err(map_argon2_error)?;
    let block_count = argon2_params.block_count();
    let context = argon2::Argon2::new_with_secret(
        secret,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    )
    .map_err(map_argon2_error)?;

    // Allocate the working memory ourselves so it is zeroized on drop; the
    // crate's own `hash_password_into` frees its blocks without wiping them.
    // `try_reserve_exact` turns allocation failure into an error instead of
    // an abort.
    let mut blocks: Zeroizing<Vec<argon2::Block>> = Zeroizing::new(Vec::new());
    blocks.try_reserve_exact(block_count).map_err(|e| {
        tracing::debug!(error = %e, block_count, "Argon2id working memory allocation failed");
        LatticeArcError::ResourceExhausted
    })?;
    blocks.resize(block_count, argon2::Block::new());

    let mut output: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; output_len]);
    context
        .hash_password_into_with_memory(password, salt, &mut output, blocks.as_mut_slice())
        .map_err(map_argon2_error)?;

    // `SecretVec::new` copies into an exact-size buffer and wipes the moved
    // vector; `Zeroizing` then drops the empty husk.
    let key = SecretVec::new(std::mem::take(&mut *output));
    Ok(Argon2idResult { key, params: *params })
}

/// Map a resource-limit failure to the crate error type.
fn map_resource_error(err: ResourceError) -> LatticeArcError {
    match err {
        ResourceError::Argon2MemoryLimitExceeded { requested_kib, limit_kib } => {
            tracing::debug!(requested_kib, limit_kib, "Argon2id memory cap exceeded");
            LatticeArcError::ResourceExhausted
        }
        other => LatticeArcError::InvalidConfiguration(other.to_string()),
    }
}

/// Map an `argon2` crate error. Its messages carry no secret data.
fn map_argon2_error(err: argon2::Error) -> LatticeArcError {
    LatticeArcError::InvalidParameter(format!("Argon2id: {err}"))
}

/// Calibration against an explicit resource-limit manager.
///
/// [`Argon2Params::calibrate`] passes the global manager; tests pass their
/// own so they can vary the cap without touching global state.
///
/// # Errors
/// See [`Argon2Params::calibrate`].
pub(crate) fn calibrate_with_limits(
    target_ms: u64,
    max_memory_kib: u32,
    limits: &ResourceLimitsManager,
) -> Result<Argon2Params> {
    if target_ms == 0 || target_ms > Argon2Params::MAX_CALIBRATION_TARGET_MS {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Argon2id calibration target {target_ms} ms outside 1..={} ms",
            Argon2Params::MAX_CALIBRATION_TARGET_MS
        )));
    }
    let limit_kib = limits.get_limits().map_err(map_resource_error)?.max_argon2_memory_kib;
    let cap_kib = max_memory_kib.min(limit_kib);
    if cap_kib < Argon2Params::MIN_MEMORY_KIB_PER_LANE {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Argon2id calibration memory cap {cap_kib} KiB below RFC 9106 minimum of {} KiB",
            Argon2Params::MIN_MEMORY_KIB_PER_LANE
        )));
    }
    let target = Duration::from_millis(target_ms);

    // Fixed inputs: Argon2id running time does not depend on input values.
    let password = [0x5a_u8; 32];
    let salt = [0xa5_u8; Argon2Params::RECOMMENDED_SALT_LEN];
    let measure = |params: &Argon2Params| -> Result<Duration> {
        let start = Instant::now();
        argon2id_inner(&password, &salt, &[], &[], params, limits)?;
        Ok(start.elapsed())
    };

    // Phase 1: grow memory at one pass until the cap or the target.
    let mut best = Argon2Params {
        memory_kib: Argon2Params::CALIBRATION_START_MEMORY_KIB.min(cap_kib),
        iterations: 1,
        parallelism: 1,
        output_len: 32,
    };
    let mut elapsed = measure(&best)?;
    while elapsed < target && best.memory_kib < cap_kib {
        let candidate =
            Argon2Params { memory_kib: best.memory_kib.saturating_mul(2).min(cap_kib), ..best };
        let candidate_elapsed = measure(&candidate)?;
        if candidate_elapsed > target {
            return Ok(best);
        }
        best = candidate;
        elapsed = candidate_elapsed;
    }
    if elapsed >= target {
        return Ok(best);
    }

    // Phase 2: memory is at the cap; scale passes linearly from the
    // one-pass time, rounding down so the estimate stays within target.
    let per_pass_ns = elapsed.as_nanos().max(1);
    // `per_pass_ns >= 1`, so `checked_div` cannot return `None`.
    let passes = target.as_nanos().checked_div(per_pass_ns).unwrap_or(1);
    best.iterations = u32::try_from(passes)
        .unwrap_or(Argon2Params::MAX_ITERATIONS)
        .clamp(Argon2Params::MIN_ITERATIONS, Argon2Params::MAX_ITERATIONS);
    best.validate()?;
    Ok(best)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
#[expect(clippy::panic, reason = "`let ... else { panic!(...) }` extracts error variants in tests")]
mod tests {
    use super::*;
    use crate::primitives::resource_limits::ResourceLimits;
    use hex_literal::hex;
    use proptest::prelude::*;

    /// Small, fast parameters for behavioural tests.
    fn small(memory_kib: u32, iterations: u32, parallelism: u32) -> Argon2Params {
        Argon2Params { memory_kib, iterations, parallelism, output_len: 32 }
    }

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SALT: &[u8] = b"0123456789abcdef";

    fn manager_with_cap(cap_kib: u32) -> ResourceLimitsManager {
        ResourceLimitsManager::with_limits(ResourceLimits {
            max_argon2_memory_kib: cap_kib,
            ..ResourceLimits::default()
        })
    }

    fn expect_invalid_parameter(result: Result<Argon2idResult>, needle: &str) {
        let Err(LatticeArcError::InvalidParameter(msg)) = result else {
            panic!("expected InvalidParameter containing {needle:?}, got {result:?}");
        };
        assert!(msg.contains(needle), "message {msg:?} should contain {needle:?}");
    }

    // ------------------------------------------------------------------
    // Known-answer tests
    // ------------------------------------------------------------------

    /// RFC 9106 §5.3 Argon2id test vector (version 0x13): m = 32 KiB, t = 3,
    /// p = 4, password 32 x 0x01, salt 16 x 0x02, secret 8 x 0x03,
    /// associated data 12 x 0x04, 32-byte tag.
    #[test]
    fn test_argon2id_rfc9106_section_5_3_vector_matches() {
        let params = small(32, 3, 4);
        let result = argon2id_inner(
            &[0x01; 32],
            &[0x02; 16],
            &[0x03; 8],
            &[0x04; 12],
            &params,
            get_global_resource_limits(),
        )
        .unwrap();
        assert_eq!(
            result.expose_secret(),
            hex!(
                "0d640df58d78766c08c037a34a8b53c9"
                "d01ef0452d75b65eb52520e96b01e659"
            )
        );
    }

    /// `(t, m_kib, p, password, salt, tag)`.
    type ReferenceCase = (u32, u32, u32, &'static [u8], &'static [u8], [u8; 32]);

    /// Argon2id v0x13 vectors from the reference implementation's test suite,
    /// `src/test.c` in <https://github.com/P-H-C/phc-winner-argon2> (the
    /// `hashtest(version, t, m, p, ...)` calls, where memory is `2^m` KiB).
    /// These go through the public [`argon2id`] API with no secret or AD.
    #[test]
    fn test_argon2id_reference_implementation_vectors_match() {
        let cases: [ReferenceCase; 5] = [
            (
                2,
                256,
                1,
                b"password",
                b"somesalt",
                hex!("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"),
            ),
            (
                2,
                256,
                2,
                b"password",
                b"somesalt",
                hex!("6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037"),
            ),
            (
                2,
                65536,
                1,
                b"password",
                b"somesalt",
                hex!("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"),
            ),
            (
                2,
                65536,
                1,
                b"differentpassword",
                b"somesalt",
                hex!("0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde"),
            ),
            (
                2,
                65536,
                1,
                b"password",
                b"diffsalt",
                hex!("bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c"),
            ),
        ];
        for (t, m, p, password, salt, expected) in cases {
            let result = argon2id(password, salt, &small(m, t, p)).unwrap();
            assert_eq!(result.expose_secret(), expected, "t={t} m={m} p={p}");
        }
    }

    // ------------------------------------------------------------------
    // Roundtrip / determinism
    // ------------------------------------------------------------------

    #[test]
    fn test_argon2id_is_deterministic() {
        let params = small(64, 1, 1);
        let a = argon2id(PASSWORD, SALT, &params).unwrap();
        let b = argon2id(PASSWORD, SALT, &params).unwrap();
        assert!(bool::from(a.ct_eq(&b)));
        assert_eq!(a.key_length(), 32);
        assert_eq!(a.params(), &params);
    }

    #[test]
    fn test_argon2id_different_passwords_produce_different_keys() {
        let params = small(64, 1, 1);
        let a = argon2id(b"password-one", SALT, &params).unwrap();
        let b = argon2id(b"password-two", SALT, &params).unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_argon2id_result_debug_redacts_key() {
        let result = argon2id(PASSWORD, SALT, &small(64, 1, 1)).unwrap();
        let debug = format!("{result:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("memory_kib: 64"));
        let hex_key: String = result.expose_secret().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!debug.contains(&hex_key));
    }

    #[test]
    fn test_argon2id_secret_input_changes_output() {
        let params = small(32, 1, 1);
        let limits = get_global_resource_limits();
        let plain = argon2id_inner(PASSWORD, SALT, &[], &[], &params, limits).unwrap();
        let public = argon2id(PASSWORD, SALT, &params).unwrap();
        let keyed = argon2id_inner(PASSWORD, SALT, &[0x03; 8], &[], &params, limits).unwrap();
        let with_ad = argon2id_inner(PASSWORD, SALT, &[], &[0x04; 12], &params, limits).unwrap();
        assert!(bool::from(plain.ct_eq(&public)), "empty secret/AD must equal public API");
        assert!(!bool::from(plain.ct_eq(&keyed)));
        assert!(!bool::from(plain.ct_eq(&with_ad)));
    }

    // ------------------------------------------------------------------
    // Config influence tests (DESIGN_PATTERNS.md Pattern 8)
    // ------------------------------------------------------------------

    #[test]
    fn test_memory_kib_influences_argon2id() {
        let a = argon2id(PASSWORD, SALT, &small(32, 1, 1)).unwrap();
        let b = argon2id(PASSWORD, SALT, &small(64, 1, 1)).unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_iterations_influences_argon2id() {
        let a = argon2id(PASSWORD, SALT, &small(32, 1, 1)).unwrap();
        let b = argon2id(PASSWORD, SALT, &small(32, 2, 1)).unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_parallelism_influences_argon2id() {
        let a = argon2id(PASSWORD, SALT, &small(32, 1, 1)).unwrap();
        let b = argon2id(PASSWORD, SALT, &small(32, 1, 2)).unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_output_len_influences_argon2id() {
        let short = Argon2Params { output_len: 16, ..small(32, 1, 1) };
        let long = Argon2Params { output_len: 64, ..small(32, 1, 1) };
        let a = argon2id(PASSWORD, SALT, &short).unwrap();
        let b = argon2id(PASSWORD, SALT, &long).unwrap();
        assert_eq!(a.expose_secret().len(), 16);
        assert_eq!(b.expose_secret().len(), 64);
        // Argon2's H' feeds the tag length into the initial hash, so a
        // shorter tag is not a prefix of a longer one.
        assert_ne!(a.expose_secret(), b.expose_secret().get(..16).unwrap());
    }

    #[test]
    fn test_max_argon2_memory_kib_influences_argon2id() {
        let params = small(64, 1, 1);
        let at_cap = argon2id_inner(PASSWORD, SALT, &[], &[], &params, &manager_with_cap(64));
        assert!(at_cap.is_ok(), "memory equal to the cap must be accepted");
        let over = argon2id_inner(PASSWORD, SALT, &[], &[], &params, &manager_with_cap(63));
        assert!(matches!(over, Err(LatticeArcError::ResourceExhausted)), "got {over:?}");
    }

    #[test]
    fn test_max_argon2_memory_kib_influences_calibrate() {
        let params = calibrate_with_limits(5, u32::MAX, &manager_with_cap(16)).unwrap();
        assert!(params.memory_kib <= 16, "calibrate must respect the resource cap");
        let params = calibrate_with_limits(5, 16, &manager_with_cap(8)).unwrap();
        assert_eq!(params.memory_kib, 8, "the smaller of the two caps wins");
    }

    #[test]
    fn test_default_global_cap_rejects_oversized_memory() {
        let params = Argon2Params { memory_kib: u32::MAX, ..small(8, 1, 1) };
        let result = argon2id(PASSWORD, SALT, &params);
        assert!(matches!(result, Err(LatticeArcError::ResourceExhausted)), "got {result:?}");
    }

    // ------------------------------------------------------------------
    // Error paths: every rejection branch
    // ------------------------------------------------------------------

    #[test]
    fn test_argon2id_empty_password_rejected() {
        expect_invalid_parameter(argon2id(b"", SALT, &small(8, 1, 1)), "password");
    }

    #[test]
    fn test_argon2id_short_salt_rejected() {
        expect_invalid_parameter(argon2id(PASSWORD, b"1234567", &small(8, 1, 1)), "salt length");
        expect_invalid_parameter(argon2id(PASSWORD, b"", &small(8, 1, 1)), "salt length");
    }

    #[test]
    fn test_argon2id_all_zero_salt_rejected() {
        expect_invalid_parameter(argon2id(PASSWORD, &[0u8; 16], &small(8, 1, 1)), "all zeros");
    }

    #[test]
    fn test_argon2id_zero_parallelism_rejected() {
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &small(8, 1, 0)), "parallelism");
    }

    #[test]
    fn test_argon2id_excess_parallelism_rejected() {
        let params = small(u32::MAX, 1, Argon2Params::MAX_PARALLELISM + 1);
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &params), "parallelism");
    }

    #[test]
    fn test_argon2id_memory_below_eight_per_lane_rejected() {
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &small(7, 1, 1)), "memory");
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &small(15, 1, 2)), "memory");
    }

    #[test]
    fn test_argon2id_iteration_bounds_rejected() {
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &small(8, 0, 1)), "iterations");
        let params = small(8, Argon2Params::MAX_ITERATIONS + 1, 1);
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &params), "iterations");
    }

    #[test]
    fn test_argon2id_output_len_bounds_rejected() {
        let short = Argon2Params { output_len: Argon2Params::MIN_OUTPUT_LEN - 1, ..small(8, 1, 1) };
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &short), "output length");
        let long = Argon2Params { output_len: Argon2Params::MAX_OUTPUT_LEN + 1, ..small(8, 1, 1) };
        expect_invalid_parameter(argon2id(PASSWORD, SALT, &long), "output length");
    }

    #[test]
    fn test_argon2id_oversized_associated_data_rejected() {
        let result = argon2id_inner(
            PASSWORD,
            SALT,
            &[],
            &[0u8; 33],
            &small(8, 1, 1),
            get_global_resource_limits(),
        );
        expect_invalid_parameter(result, "Argon2id:");
    }

    #[test]
    fn test_map_resource_error_lock_poisoned_is_invalid_configuration() {
        let err = map_resource_error(ResourceError::LockPoisoned);
        assert!(matches!(err, LatticeArcError::InvalidConfiguration(_)), "got {err:?}");
    }

    #[test]
    fn test_argon2_params_new_validates() {
        assert!(Argon2Params::new(8, 1, 1, 16).is_ok());
        assert!(Argon2Params::new(7, 1, 1, 16).is_err());
        assert!(Argon2Params::new(8, 0, 1, 16).is_err());
        assert!(Argon2Params::new(8, 1, 0, 16).is_err());
        assert!(Argon2Params::new(8, 1, 1, 15).is_err());
    }

    // ------------------------------------------------------------------
    // Boundaries
    // ------------------------------------------------------------------

    #[test]
    fn test_argon2id_minimum_parameters_succeed() {
        let params = Argon2Params::new(
            Argon2Params::MIN_MEMORY_KIB_PER_LANE,
            Argon2Params::MIN_ITERATIONS,
            Argon2Params::MIN_PARALLELISM,
            Argon2Params::MIN_OUTPUT_LEN,
        )
        .unwrap();
        let result = argon2id(b"p", b"8bytes!!", &params).unwrap();
        assert_eq!(result.key_length(), Argon2Params::MIN_OUTPUT_LEN);
    }

    #[test]
    fn test_argon2id_maximum_output_len_succeeds() {
        let params = Argon2Params { output_len: Argon2Params::MAX_OUTPUT_LEN, ..small(8, 1, 1) };
        let result = argon2id(PASSWORD, SALT, &params).unwrap();
        assert_eq!(result.key_length(), Argon2Params::MAX_OUTPUT_LEN);
    }

    #[test]
    fn test_argon2id_maximum_iterations_accepted_by_validate() {
        assert!(Argon2Params::new(8, Argon2Params::MAX_ITERATIONS, 1, 32).is_ok());
    }

    #[test]
    fn test_argon2id_maximum_parallelism_accepted_by_validate() {
        let p = Argon2Params::MAX_PARALLELISM;
        assert!(Argon2Params::new(p * 8, 1, p, 32).is_ok());
    }

    #[test]
    fn test_argon2id_salt_length_boundaries() {
        let params = small(8, 1, 1);
        assert!(argon2id(PASSWORD, b"12345678", &params).is_ok(), "8-byte salt is the floor");
        assert!(argon2id(PASSWORD, &[0x11; 1024], &params).is_ok(), "long salt accepted");
    }

    #[test]
    fn test_argon2_params_default_profile() {
        let params = Argon2Params::default();
        assert_eq!(params, Argon2Params::new(65536, 3, 1, 32).unwrap());
        assert!(params.validate().is_ok());
    }

    // ------------------------------------------------------------------
    // Calibration (bounds only; no wall-clock assertions)
    // ------------------------------------------------------------------

    #[test]
    fn test_calibrate_returns_valid_params_within_cap() {
        let params = Argon2Params::calibrate(10, 256).unwrap();
        assert!(params.validate().is_ok());
        assert!(params.memory_kib <= 256);
        assert!(params.memory_kib >= Argon2Params::MIN_MEMORY_KIB_PER_LANE);
        assert_eq!(params.parallelism, 1);
        assert_eq!(params.output_len, 32);
        assert!(argon2id(PASSWORD, SALT, &params).is_ok(), "calibrated params must derive");
    }

    #[test]
    fn test_calibrate_rejects_invalid_inputs() {
        assert!(Argon2Params::calibrate(0, 1024).is_err(), "zero target");
        let too_long = Argon2Params::MAX_CALIBRATION_TARGET_MS + 1;
        assert!(Argon2Params::calibrate(too_long, 1024).is_err(), "target above maximum");
        assert!(Argon2Params::calibrate(10, 7).is_err(), "cap below RFC minimum");
    }

    // ------------------------------------------------------------------
    // Property tests
    // ------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_argon2id_deterministic(
            password in proptest::collection::vec(any::<u8>(), 1..64),
            salt in proptest::collection::vec(1u8..=255, 8..32),
        ) {
            let params = small(8, 1, 1);
            let a = argon2id(&password, &salt, &params).unwrap();
            let b = argon2id(&password, &salt, &params).unwrap();
            prop_assert!(bool::from(a.ct_eq(&b)));
        }

        #[test]
        fn prop_argon2id_distinct_salts_distinct_outputs(
            password in proptest::collection::vec(any::<u8>(), 1..64),
            salt_a in proptest::collection::vec(1u8..=255, 8..32),
            salt_b in proptest::collection::vec(1u8..=255, 8..32),
        ) {
            prop_assume!(salt_a != salt_b);
            let params = small(8, 1, 1);
            let a = argon2id(&password, &salt_a, &params).unwrap();
            let b = argon2id(&password, &salt_b, &params).unwrap();
            prop_assert!(!bool::from(a.ct_eq(&b)));
        }
    }
}
