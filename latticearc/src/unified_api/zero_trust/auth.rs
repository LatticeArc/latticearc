//! `ZeroTrustAuth`: the challenge/proof/PoP/continuous-verification handler,
//! plus its private replay cache.

use super::proof_data::generate_challenge_data;
use super::{Challenge, ContinuousSession, ProofOfPossessionData, ZeroKnowledgeProof};
use crate::primitives::ec::ed25519::ED25519_PUBLIC_KEY_LEN;
use crate::types::traits::{
    ContinuousVerifiable, ProofOfPossession, VerificationStatus, ZeroTrustAuthenticable,
};
use crate::unified_api::{
    ZeroTrustConfig,
    error::{CoreError, Result},
};
use crate::{
    log_zero_trust_challenge_generated, log_zero_trust_proof_verified,
    types::{PrivateKey, PublicKey},
};
use chrono::{DateTime, Utc};
use std::sync::Mutex;
use subtle::ConstantTimeEq;

// ============================================================================
// Zero Trust Authentication Handler
// ============================================================================

/// Zero-trust authentication handler.
///
/// Manages challenge-response authentication, proof generation and verification,
/// and continuous session monitoring.
pub struct ZeroTrustAuth {
    /// Public key for verification.
    pub(crate) public_key: PublicKey,
    /// Private key for proof generation.
    ///
    /// `pub(super)`: read by the `compute_proof_data` /
    /// `verify_proof_data` helpers in `zero_trust::proof_data`.
    pub(super) private_key: PrivateKey,
    /// Authentication configuration.
    ///
    /// `pub(super)`: read by `zero_trust::proof_data` (proof-complexity
    /// dispatch) in addition to this module's own trait impls.
    pub(super) config: ZeroTrustConfig,
    /// Session start timestamp.
    session_start: DateTime<Utc>,
    /// Timestamp of the most recent successful proof verification, or
    /// `None` if no proof has yet been verified for this auth instance.
    ///
    /// The `None` ↔ `Some` boundary is the precondition gate for
    /// [`Self::start_continuous_verification`]: starting a continuous
    /// session before any successful challenge-response would let a
    /// fresh `ZeroTrustAuth` skip the ZKP handshake entirely.
    ///
    /// `Mutex` (not `RefCell`) so the type stays `Sync` for use across
    /// async tasks and multi-threaded callers; an `Arc<ZeroTrustAuth>`
    /// shared between Tokio workers must compile.
    last_verification: Mutex<Option<DateTime<Utc>>>,
    /// Replay cache for proofs-of-possession.
    ///
    /// Keyed on `pk || sig || ts_micros_be` (microsecond precision —
    /// see the M16 follow-up note in `generate_pop` for why second
    /// precision was insufficient under Ed25519's deterministic
    /// signatures). Values are the wall-clock seconds-since-epoch at
    /// which the entry was inserted (used to bound cache lifetime to
    /// the 5-minute PoP freshness window).
    ///
    /// Carries a parallel `per_pk_counts` map so the per-PK quota check
    /// is O(1). Without it, the global cap alone would let a single
    /// noisy public key fill the cache and lock out every other PK
    /// (DoS against legitimate verifiers); with it, each PK is bounded
    /// to `POP_CACHE_PER_PK_MAX` entries and other PKs proceed normally.
    ///
    /// `Mutex` (not `RefCell`) so the type stays `Sync` for use across
    /// async/multi-threaded callers.
    pop_replay_cache: Mutex<PopReplayCache>,
}

/// Internal helper: a replay cache that tracks both the full
/// `(pk || sig || ts_micros)` entries and a per-PK count alongside.
/// The two maps are mutated together under the surrounding `Mutex` so
/// the per-PK count is always exact, never a stale approximation.
///
/// `pk_len` is fixed at construction (currently
/// [`ED25519_PUBLIC_KEY_LEN`]) and is the authoritative length of the
/// public-key prefix in every entry key. Mixing entries with different
/// PK lengths would break the inverse-of-insert assumption in
/// `expire_older_than` (the prefix slice would misidentify which entry
/// belongs to which PK), silently leak per-PK quota state, and degrade
/// the M2 fail-closed replay invariant. The `pk_len` field plus the
/// debug-assert in [`Self::insert`] enforce uniformity at the
/// API boundary so a future PoP type with a different PK length cannot
/// silently coexist with the current one — adding such a type must
/// either create a separate cache instance or extend the entry-key
/// encoding to disambiguate.
struct PopReplayCache {
    /// Authoritative public-key prefix length. Set once at
    /// construction; every `insert` debug-asserts that the supplied
    /// `pk_bytes` length matches this value.
    pk_len: usize,
    /// Full keys (PK || sig || ts_micros) → insertion timestamp (seconds).
    entries: std::collections::HashMap<Vec<u8>, i64>,
    /// Public-key bytes → count of `entries` belonging to that PK.
    /// Maintained in lockstep with `entries`; never read independently.
    per_pk_counts: std::collections::HashMap<Vec<u8>, usize>,
}

impl PopReplayCache {
    /// Construct an empty cache for entries whose PK prefix is exactly
    /// `pk_len` bytes. Today the only caller passes
    /// [`ED25519_PUBLIC_KEY_LEN`]; if a future PoP type uses a
    /// different PK length, give it its own `PopReplayCache` rather
    /// than mixing prefixes here.
    fn new(pk_len: usize) -> Self {
        Self {
            pk_len,
            entries: std::collections::HashMap::new(),
            per_pk_counts: std::collections::HashMap::new(),
        }
    }

    /// Remove entries older than `max_age_secs` and update per-PK counts
    /// to match. The leading `self.pk_len` bytes of every entry key are
    /// the public-key bytes; this is the inverse of how `insert` builds
    /// the key, and is only well-defined because `insert` debug-asserts
    /// every inserted `pk_bytes` matches `self.pk_len`.
    fn expire_older_than(&mut self, now_secs: i64, max_age_secs: i64) {
        let pk_len = self.pk_len;
        let entries = &mut self.entries;
        let per_pk = &mut self.per_pk_counts;
        entries.retain(|key, ts| {
            let fresh = now_secs.saturating_sub(*ts) <= max_age_secs;
            if !fresh
                && let Some(pk_bytes) = key.get(..pk_len)
                && let Some(count) = per_pk.get_mut(pk_bytes)
            {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_pk.remove(pk_bytes);
                }
            }
            fresh
        });
    }

    fn contains(&self, key: &[u8]) -> bool {
        self.entries.contains_key(key)
    }

    fn count_for_pk(&self, pk_bytes: &[u8]) -> usize {
        self.per_pk_counts.get(pk_bytes).copied().unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.entries.len()
    }

    fn insert(&mut self, pk_bytes: &[u8], full_key: Vec<u8>, ts_secs: i64) {
        // Guards the `pk_len` uniformity invariant the rest of this
        // type relies on. A mismatch here means the caller mixed PoP
        // types into one cache; the per-PK count would key off a
        // wrong-length prefix and `expire_older_than` would never
        // decrement it, silently leaking quota. Dev/CI surface only —
        // production stays branch-free in the hot path.
        debug_assert_eq!(
            pk_bytes.len(),
            self.pk_len,
            "PopReplayCache: pk_bytes.len()={} does not match cache pk_len={}; \
             mixing PoP key types in one cache silently breaks per-PK quota tracking",
            pk_bytes.len(),
            self.pk_len,
        );
        if self.entries.insert(full_key, ts_secs).is_none() {
            let slot = self.per_pk_counts.entry(pk_bytes.to_vec()).or_insert(0);
            *slot = slot.saturating_add(1);
        }
    }
}

impl ZeroTrustAuth {
    /// Creates a new `ZeroTrustAuth` instance with default configuration.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` if the default configuration is invalid
    /// (e.g., maximum security level without hardware acceleration, or speed preference
    /// without fallback enabled).
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        let config = ZeroTrustConfig::default();
        config.validate()?;

        let now = Utc::now();
        Ok(Self {
            public_key,
            private_key,
            config,
            session_start: now,
            // `None` until the first successful proof verification —
            // see field doc.
            last_verification: Mutex::new(None),
            pop_replay_cache: Mutex::new(PopReplayCache::new(ED25519_PUBLIC_KEY_LEN)),
        })
    }

    /// Creates a new `ZeroTrustAuth` instance with the provided configuration.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` if:
    /// - The challenge timeout is zero.
    /// - Continuous verification is enabled but the verification interval is zero.
    /// - The base configuration is invalid (e.g., maximum security level without
    ///   hardware acceleration).
    pub fn with_config(
        public_key: PublicKey,
        private_key: PrivateKey,
        config: ZeroTrustConfig,
    ) -> Result<Self> {
        config.validate()?;

        let now = Utc::now();
        Ok(Self {
            public_key,
            private_key,
            config,
            session_start: now,
            last_verification: Mutex::new(None),
            pop_replay_cache: Mutex::new(PopReplayCache::new(ED25519_PUBLIC_KEY_LEN)),
        })
    }

    /// Generate a new challenge for authentication.
    ///
    /// # Errors
    /// Returns `CoreError::EntropyDepleted` if the system cannot generate random bytes.
    pub fn generate_challenge(&self) -> Result<Challenge> {
        let challenge_data = generate_challenge_data(&self.config.proof_complexity)?;
        log_zero_trust_challenge_generated!(self.config.proof_complexity);
        Ok(Challenge {
            data: challenge_data,
            timestamp: Utc::now(),
            complexity: self.config.proof_complexity.clone(),
            timeout_ms: self.config.challenge_timeout_ms,
        })
    }

    /// Verifies whether a challenge is still within its timeout period.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    pub fn verify_challenge_age(&self, challenge: &Challenge) -> Result<bool> {
        let elapsed = Utc::now().signed_duration_since(challenge.timestamp());
        let elapsed_ms = elapsed.num_milliseconds();

        // Negative elapsed time means the challenge is from the future, which is invalid
        // Convert safely: negative values are treated as invalid (elapsed > timeout)
        let elapsed_u64 = u64::try_from(elapsed_ms).unwrap_or(u64::MAX);
        Ok(elapsed_u64 <= challenge.timeout_ms())
    }

    /// Starts a new continuous verification session.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if no successful
    /// challenge-response has occurred for this `ZeroTrustAuth`
    /// instance. Continuous verification is supposed to *extend* a
    /// trust relationship that was already established cryptographically;
    /// without this gate, a freshly-constructed `ZeroTrustAuth` could
    /// hand out a `ContinuousSession` whose `is_valid()` returns true,
    /// bypassing the ZKP handshake entirely.
    pub fn start_continuous_verification(&self) -> Result<ContinuousSession> {
        let last_verified = match self.last_verification.lock() {
            Ok(g) => *g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "latticearc::unified_api::zero_trust",
                    "ZeroTrustAuth.last_verification mutex was poisoned in \
                     start_continuous_verification; a previous writer panicked. \
                     Recovering inner guard."
                );
                *poisoned.into_inner()
            }
        };
        let last_verified = last_verified.ok_or_else(|| {
            CoreError::AuthenticationFailed(
                "start_continuous_verification requires a prior successful proof verification \
                 (call verify_proof() against a fresh challenge first)"
                    .to_string(),
            )
        })?;
        Ok(ContinuousSession {
            auth_public_key: self.public_key.clone(),
            start_time: Utc::now(),
            verification_interval_ms: self.config.verification_interval_ms,
            last_verification: last_verified,
        })
    }
}

impl ZeroTrustAuthenticable for ZeroTrustAuth {
    type Proof = ZeroKnowledgeProof;
    type Error = CoreError;

    /// Generates a zero-knowledge proof for the given challenge.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if the challenge is empty.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the private key has incorrect length
    /// for Ed25519 signing.
    ///
    /// Returns `CoreError::InvalidInput` if the private key format is invalid.
    fn generate_proof(&self, challenge: &[u8]) -> Result<Self::Proof> {
        if challenge.is_empty() {
            return Err(CoreError::AuthenticationFailed("Empty challenge".to_string()));
        }

        let proof_data = self.compute_proof_data(challenge)?;
        let timestamp = Utc::now();

        Ok(ZeroKnowledgeProof {
            challenge: challenge.to_vec(),
            proof: proof_data,
            timestamp,
            complexity: self.config.proof_complexity.clone(),
        })
    }

    /// Verifies a zero-knowledge proof against the given challenge.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if the proof format is invalid
    /// (e.g., timestamp bytes cannot be extracted for Medium/High complexity proofs).
    ///
    /// Returns `CoreError::InvalidInput` if the public key or signature format is invalid
    /// during Ed25519 verification.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the public key has incorrect length.
    fn verify_proof(
        &self,
        proof: &Self::Proof,
        challenge: &[u8],
    ) -> std::result::Result<bool, Self::Error> {
        // The prover writes `proof.complexity` from its own config but
        // the verifier previously only consulted
        // `self.config.proof_complexity` for dispatch — so a prover
        // claiming Low complexity could ship a proof verified under
        // the verifier's Medium policy (or vice versa). Pin the field
        // by requiring it to match the verifier's expected complexity;
        // mismatch collapses to `Ok(false)` (Pattern 6 — no
        // distinguishable error per audit posture).
        if proof.complexity() != &self.config.proof_complexity {
            tracing::debug!(
                expected = ?self.config.proof_complexity,
                got = ?proof.complexity(),
                "ZK proof rejected: complexity field mismatch"
            );
            log_zero_trust_proof_verified!(false);
            return Ok(false);
        }

        // SECURITY: Use constant-time comparison to prevent timing attacks
        // An attacker should not be able to determine which bytes of the challenge matched
        let len_eq = proof.challenge().len().ct_eq(&challenge.len());
        let content_eq = proof.challenge().ct_eq(challenge);
        let challenge_matches: bool = (len_eq & content_eq).into();

        if !challenge_matches {
            log_zero_trust_proof_verified!(false);
            return Ok(false);
        }

        let result = self.verify_proof_data(proof.proof_data(), challenge)?;
        if result {
            // Bump the last-verified timestamp so subsequent calls to
            // `start_continuous_verification` and the elapsed-time
            // gate in `maybe_continuous_verification` observe a real
            // handshake rather than a fresh `None`. Recover from
            // poison: a panicked writer would only have been writing
            // a `Utc::now()` value; the cached timestamp is still
            // valid.
            let mut guard = match self.last_verification.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!(
                        target: "latticearc::unified_api::zero_trust",
                        "ZeroTrustAuth.last_verification mutex was poisoned in \
                         verify_proof success path; a previous writer panicked. \
                         Recovering inner guard."
                    );
                    poisoned.into_inner()
                }
            };
            *guard = Some(Utc::now());
        }
        log_zero_trust_proof_verified!(result);
        Ok(result)
    }
}

/// Build the PoP transcript digest used by `generate_pop` / `verify_pop`.
///
/// Encodes
/// `SHA-512(pop_ctx || 0x00 || verifier_pk_len_be4 || verifier_pk
/// || 0x00 || ts_micros_be8 || 0x00 || challenge_len_be4 || challenge)`.
///
/// `verifier_pk` and `challenge` are each length-prefixed with a
/// big-endian u32 so that concatenation cannot ambiguously parse as a
/// different `(verifier_pk, challenge)` split. The 0x00 separators add
/// a NUL-safety belt because `SIG_CONTEXT_POP_ED25519` is asserted
/// NUL-free by its module-level test.
///
/// Sized [u8; 64] output. Returned by value so the digest lives in
/// a register / stack slot the compiler can scrub.
fn pop_transcript_digest(verifier_pk: &[u8], ts_micros: i64, challenge: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(crate::types::domains::pop_sig_context());
    hasher.update([0x00]);
    // Pre-encode the length prefixes as fixed-size arrays so the
    // `.update(&[..])` calls stay branch-free and cannot be tricked by
    // a future signature change that exposes a `usize`-vs-`u32` cast
    // mistake. `.len() as u32` is bounded by the underlying slice cap
    // (Ed25519 PK = 32 B, server-issued challenge ≤ 64 KiB at most for
    // any sane caller).
    let pk_len: u32 = verifier_pk.len().try_into().unwrap_or(u32::MAX);
    hasher.update(pk_len.to_be_bytes());
    hasher.update(verifier_pk);
    hasher.update([0x00]);
    hasher.update(ts_micros.to_be_bytes());
    hasher.update([0x00]);
    let ch_len: u32 = challenge.len().try_into().unwrap_or(u32::MAX);
    hasher.update(ch_len.to_be_bytes());
    hasher.update(challenge);
    hasher.finalize().into()
}

impl ProofOfPossession for ZeroTrustAuth {
    type Pop = ProofOfPossessionData;
    type Error = CoreError;

    /// Generates a proof of possession bound to a caller-supplied
    /// challenge.
    ///
    /// The signed transcript is
    /// `SHA-512(pop_ctx || 0x00 || verifier_pk_len_be4 || verifier_pk
    /// || 0x00 || ts_micros_be8 || 0x00 || challenge_len_be4 ||
    /// challenge)`. Binding `self.public_key` (the verifier identity this
    /// auth represents) closes cross-identity replay; binding `challenge`
    /// closes cross-verifier-instance replay within the freshness window.
    /// Both are length-prefixed to prevent prefix-free ambiguity between
    /// the two adjacent variable-length values.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidKeyLength` if the private key has
    /// incorrect length for Ed25519 signing. Returns
    /// `CoreError::InvalidInput` if the private key format is invalid.
    fn generate_pop(&self, challenge: &[u8]) -> Result<Self::Pop> {
        // PoP-M1 follow-up: empty challenge silently disables cross-
        // verifier-instance replay protection. The wire format encodes
        // challenge_len so the signature still differs from an
        // unbound-challenge legacy PoP, but a verifier that calls
        // generate_pop(b"") and verify_pop(_, b"") accepts cross-
        // verifier replays for the freshness window. Warn loudly at
        // sign-side so operators don't ship the misuse silently;
        // verify-side rejects with Err so silent fall-through is
        // impossible.
        if challenge.is_empty() {
            tracing::warn!(
                "PoP generate_pop called with empty challenge — cross-verifier-\
                 instance replay protection requires a per-request nonce. \
                 verify_pop will refuse to accept an empty challenge."
            );
        }
        let timestamp = Utc::now();
        // Microsecond precision: Ed25519 sigs are deterministic, so two
        // PoPs in the same second from the same key produce identical
        // wire bytes and trip the replay cache against a legitimate
        // client regenerating in a tight loop. Microseconds also fit
        // comfortably inside the 5-minute freshness window.
        let ts_micros = timestamp.timestamp_micros();
        let pop_digest = pop_transcript_digest(self.public_key.as_slice(), ts_micros, challenge);

        let signature = crate::unified_api::convenience::ed25519::sign_ed25519_internal(
            &pop_digest,
            self.private_key.expose_secret(),
        )?;

        Ok(ProofOfPossessionData { public_key: self.public_key.clone(), signature, timestamp })
    }

    /// Verifies a proof of possession against `self.public_key` and the
    /// caller-supplied expected challenge.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is fresh AND identity-bound AND
    /// challenge-bound AND cryptographically valid. `Ok(false)` for
    /// every rejection cause — stale, future-dated, identity mismatch
    /// (PoP-H1), challenge mismatch (PoP-M1), crypto reject, replay
    /// within the freshness window. **All adversary-reachable rejection
    /// causes collapse to `Ok(false)`** so callers cannot distinguish
    /// "stale, refresh and retry" from "wrong PoP" / "replay" by
    /// branching on the Result. Rejection cause is logged at
    /// `tracing::debug!` for operator visibility.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidInput` only for unrecoverable
    /// structural failures (poisoned mutex on the replay cache). The
    /// signature-length, public-key-length, and stale / future / replay
    /// paths are all Pattern-6-collapsed to `Ok(false)`.
    fn verify_pop(
        &self,
        pop: &Self::Pop,
        expected_challenge: &[u8],
    ) -> std::result::Result<bool, Self::Error> {
        // PoP-M1 follow-up: refuse empty challenge. An operator that
        // generates PoPs with empty challenge and verifies them with
        // empty challenge structurally loses the cross-verifier-
        // instance replay protection the parameter exists to provide
        // — the wrapper bytes still differ from pre-fix raw-message
        // PoPs, but a verifier that consistently passes b"" would
        // accept cross-verifier replays for the freshness window. Hard
        // reject is operator-misuse class, not adversary-attainable,
        // so Err (not Ok(false)) is appropriate — distinguishing
        // "missing challenge" from "wrong challenge" doesn't leak
        // adversary-controllable state.
        if expected_challenge.is_empty() {
            return Err(CoreError::InvalidInput(
                "PoP verify_pop requires a non-empty expected_challenge — the \
                 per-request nonce is the only structural defence against \
                 cross-verifier-instance replay. Pass the same bytes the \
                 generator used."
                    .to_string(),
            ));
        }
        // Freshness check: reject proofs older than PROOF_OF_POSSESSION_MAX_AGE.
        // This prevents replay of stale PoPs captured from prior sessions (P5.2 C4).
        // Using chrono::Duration so the bound is expressed in seconds regardless
        // of timezone or DST quirks.
        const PROOF_OF_POSSESSION_MAX_AGE_SECS: i64 = 5 * 60; // 5 minutes
        let elapsed = Utc::now().signed_duration_since(pop.timestamp());
        if elapsed.num_seconds() > PROOF_OF_POSSESSION_MAX_AGE_SECS {
            // Pattern-6: do not leak elapsed seconds or the configured
            // max age via the error string. An adversary with a PoP-
            // generation oracle could otherwise narrow server clock
            // skew to seconds. Cause logged at tracing::debug! for
            // operators.
            tracing::debug!(
                elapsed_secs = elapsed.num_seconds(),
                max_age_secs = PROOF_OF_POSSESSION_MAX_AGE_SECS,
                "verify_pop rejected: proof-of-possession too old"
            );
            return Ok(false);
        }
        // Also reject proofs dated more than 30 seconds in the future (clock skew tolerance).
        if elapsed.num_seconds() < -30 {
            tracing::debug!(
                elapsed_secs = elapsed.num_seconds(),
                "verify_pop rejected: proof-of-possession timestamp is in the future"
            );
            return Ok(false);
        }

        // PoP-H1: identity binding. The pre-fix verify dispatched against
        // `pop.public_key()` — the public key the (potentially attacker-
        // controlled) PoP carries. Any party with any Ed25519 keypair
        // could then produce a self-signed PoP that returned Ok(true),
        // proving possession of A KEY, not THIS IDENTITY's key. Compare
        // the embedded pk against the verifier identity in constant
        // time; mismatch is Pattern-6-collapsed to Ok(false) so the
        // adversary cannot distinguish "wrong identity" from "wrong
        // signature" by branching on the Result.
        use subtle::ConstantTimeEq;
        let embedded_pk = pop.public_key().as_slice();
        let verifier_pk = self.public_key.as_slice();
        if embedded_pk.len() != verifier_pk.len() {
            tracing::debug!(
                embedded_len = embedded_pk.len(),
                verifier_len = verifier_pk.len(),
                "verify_pop rejected: embedded public key length differs from \
                 verifier identity (PoP-H1)"
            );
            return Ok(false);
        }
        if embedded_pk.ct_eq(verifier_pk).unwrap_u8() != 1u8 {
            tracing::debug!(
                "verify_pop rejected: embedded public key does not match verifier \
                 identity (PoP-H1)"
            );
            return Ok(false);
        }

        // PoP-M1: reconstruct the post-fix transcript exactly as
        // `generate_pop` produced it — verifier_pk + ts + challenge —
        // and dispatch against the verifier identity. A captured PoP
        // for a different verifier-id OR a different challenge round
        // produces a different digest and the crypto verify rejects.
        let ts_micros = pop.timestamp().timestamp_micros();
        let pop_digest = pop_transcript_digest(verifier_pk, ts_micros, expected_challenge);

        let valid = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
            &pop_digest,
            pop.signature(),
            verifier_pk,
        )?;

        // reject re-presentation of a
        // verified PoP within the 5-minute acceptance window. Without
        // a cache, an attacker who captured a single valid PoP at
        // time T could replay it any number of times within
        // (T, T + 5 min). The cache is keyed on (pk, sig, ts_micros);
        // entries older than the freshness window above are
        // self-evicting since the freshness check would already have
        // rejected them on a re-replay attempt. The signature alone
        // is byte-unique per timestamp under Ed25519 determinism (see
        // `generate_pop` for why microsecond precision is necessary),
        // so the cache key only needs to disambiguate within a single
        // microsecond.
        if valid {
            let mut cache = self.pop_replay_cache.lock().map_err(|_poison| {
                CoreError::InvalidInput("PoP replay cache poisoned".to_string())
            })?;
            // PoP-H1 enforced verifier_pk above, so the cache key uses
            // verifier_pk (the canonical identity bytes) instead of the
            // adversary-supplied `pop.public_key()`. Identical bytes by
            // construction once H1 passes, but anchoring to the verifier
            // makes the cache-key invariant resilient to future code
            // motion that might forget to dereference `pop.public_key()`
            // first.
            let pk_bytes = verifier_pk;
            let pk_len = pk_bytes.len();
            // Evict expired entries opportunistically; per-PK counts are
            // decremented in lockstep so they stay exact. `pk_len` is
            // owned by the cache (locked at construction) so this call
            // no longer carries it as a parameter.
            let now_secs = Utc::now().timestamp();
            cache.expire_older_than(now_secs, PROOF_OF_POSSESSION_MAX_AGE_SECS);
            // Cache key combines PK + signature + microsecond timestamp;
            // collisions require either a cryptographic break or a
            // deliberate replay (the latter is what we're rejecting
            // here). The challenge bytes already factor into the
            // signature (PoP-M1), so adding them to the key would be
            // redundant.
            let key_cap = pk_len.saturating_add(pop.signature().len()).saturating_add(8);
            let mut key = Vec::with_capacity(key_cap);
            key.extend_from_slice(pk_bytes);
            key.extend_from_slice(pop.signature());
            key.extend_from_slice(&ts_micros.to_be_bytes());
            if cache.contains(&key) {
                // PoP-L1: collapse replay to Ok(false). Pre-fix this was
                // Err(CoreError::InvalidInput("replay detected")), letting
                // the caller distinguish "I've seen this before" from the
                // sibling "stale, refresh and retry" path (which already
                // returned Ok(false)). Pattern-6 contract requires every
                // adversary-attainable rejection to look identical.
                tracing::debug!(ts_micros, "PoP rejected: replay within 5-min window");
                return Ok(false);
            }
            // Per-PK quota. Bounds the damage a single noisy public key can
            // do: an attacker submitting many legitimate PoPs from one PK
            // fills only their own slice of the cache, leaving every other
            // PK's quota untouched. A 64-flight legitimate client (long
            // poll, batched signing) still fits; ≥ 256 distinct PKs are
            // required before the global cap can be saturated.
            const POP_CACHE_PER_PK_MAX: usize = 64;
            if cache.count_for_pk(pk_bytes) >= POP_CACHE_PER_PK_MAX {
                // PoP-L1: collapse to Ok(false) — same Pattern-6
                // requirement as the replay-detected branch. An attacker
                // who floods their own PK to the quota cap could
                // otherwise distinguish "valid-but-quota-exhausted" (Err)
                // from "valid replay" (Ok(false)) or "invalid sig"
                // (Ok(false)) by branching on the Result variant. The
                // leaked bit is DoS-cache state, not key material, but
                // the contract documented on verify_pop says "all
                // adversary-reachable rejection causes collapse to
                // Ok(false)". Operator cause stays in tracing::warn!.
                tracing::warn!(
                    per_pk_cap = POP_CACHE_PER_PK_MAX,
                    "PoP per-key quota exhausted; rejecting new PoP from this PK \
                     (other PKs unaffected)"
                );
                return Ok(false);
            }
            // Global cap. The opportunistic eviction above already removed
            // entries older than the freshness window, so reaching this
            // cap means ≥ `POP_CACHE_MAX` distinct legitimate PoPs from
            // ≥ `POP_CACHE_MAX / POP_CACHE_PER_PK_MAX` distinct PKs were
            // verified inside a single 5-minute window — that is DoS-class
            // load. Silently skipping the insert would lift the replay
            // window for subsequent presentations of the same PoP. Fail
            // closed instead.
            const POP_CACHE_MAX: usize = 16 * 1024;
            if cache.total() >= POP_CACHE_MAX {
                // PoP-L1: same Pattern-6 rationale as the per-PK quota
                // branch above — adversary-distinguishable Err vs
                // Ok(false) was the exact oracle the L1 fix was supposed
                // to close. Operator cause stays in tracing::warn!.
                tracing::warn!(
                    cap = POP_CACHE_MAX,
                    "PoP global replay cache full; rejecting new PoP rather than \
                     skipping insert (silently skipping would re-open the 5-minute \
                     replay window)"
                );
                return Ok(false);
            }
            cache.insert(pk_bytes, key, now_secs);
        }

        Ok(valid)
    }
}

impl ContinuousVerifiable for ZeroTrustAuth {
    type Error = CoreError;

    /// Checks the current verification status of the session.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    fn verify_continuously(&self) -> Result<VerificationStatus> {
        let session_elapsed = Utc::now().signed_duration_since(self.session_start);

        let max_session_time: u64 = 30 * 60 * 1000;

        // Convert safely: negative elapsed times treated as 0 (just started)
        let session_elapsed_u64 = u64::try_from(session_elapsed.num_milliseconds()).unwrap_or(0);
        if session_elapsed_u64 > max_session_time {
            return Ok(VerificationStatus::Expired);
        }

        if !self.config.continuous_verification {
            return Ok(VerificationStatus::Verified);
        }

        // Recover from poison: a panicked write would only have been a
        // failed `Utc::now()` assignment; the cached timestamp is still
        // valid. Treating poison as fatal would lock callers out of an
        // otherwise healthy auth session.
        let last_verification_at = match self.last_verification.lock() {
            Ok(g) => *g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "latticearc::unified_api::zero_trust",
                    "ZeroTrustAuth.last_verification mutex was poisoned in \
                     maybe_continuous_verification; a previous writer panicked. \
                     Recovering inner guard."
                );
                *poisoned.into_inner()
            }
        };
        // No prior verification ⇒ continuous-verify mode reports
        // `Pending`, mirroring the "must reauthenticate" path. We never
        // return `Verified` for an instance that has never completed a
        // proof, even if the configured interval hasn't expired.
        let Some(last_verification_at) = last_verification_at else {
            return Ok(VerificationStatus::Pending);
        };
        let verification_elapsed = Utc::now().signed_duration_since(last_verification_at);

        // Convert safely: negative elapsed times treated as 0 (just verified)
        let verification_elapsed_u64 =
            u64::try_from(verification_elapsed.num_milliseconds()).unwrap_or(0);
        if verification_elapsed_u64 > self.config.verification_interval_ms {
            return Ok(VerificationStatus::Pending);
        }

        Ok(VerificationStatus::Verified)
    }

    /// Performs reauthentication by generating and verifying a new challenge-proof pair.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::EntropyDepleted` if the system cannot generate random bytes
    /// for the challenge.
    ///
    /// Returns `CoreError::AuthenticationFailed` if proof generation fails due to an
    /// empty challenge.
    ///
    /// Returns `CoreError::InvalidKeyLength` or `CoreError::InvalidInput` if the private
    /// key format is invalid for Ed25519 signing.
    fn reauthenticate(&self) -> Result<()> {
        // The previous implementation generated a proof, discarded it
        // via `let _proof = ...`, and bumped `last_verification`
        // regardless. That made `last_verification` a "now" stamp on
        // every call — an attacker who tampered with the private-key
        // bytes (use-after-free, fuzz target, etc.) kept the session
        // perpetually `Verified`. We now actually verify the proof
        // against the challenge before bumping `last_verification`, and
        // surface a hard error on mismatch.
        let challenge = self.generate_challenge()?;
        let proof = self.generate_proof(challenge.data())?;

        let proof_valid = self.verify_proof(&proof, challenge.data())?;
        if !proof_valid {
            return Err(CoreError::AuthenticationFailed(
                "Reauthentication proof verification failed".to_string(),
            ));
        }

        let mut guard = match self.last_verification.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "latticearc::unified_api::zero_trust",
                    "ZeroTrustAuth.last_verification mutex was poisoned in \
                     reauthenticate; a previous writer panicked. Recovering inner guard."
                );
                poisoned.into_inner()
            }
        };
        *guard = Some(Utc::now());
        Ok(())
    }
}
