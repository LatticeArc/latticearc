//! Challenge-data generation and the private proof-construction /
//! proof-verification helpers behind `ZeroTrustAuth::generate_proof` and
//! `ZeroTrustAuth::verify_proof`.

use super::ZeroTrustAuth;
use crate::unified_api::{
    ProofComplexity,
    error::{CoreError, Result},
};
use chrono::Utc;

/// `pub(super)`: called from `zero_trust::auth::ZeroTrustAuth::generate_challenge`.
pub(super) fn generate_challenge_data(complexity: &ProofComplexity) -> Result<Vec<u8>> {
    let size = match complexity {
        ProofComplexity::Low => 32,
        ProofComplexity::Medium => 64,
        ProofComplexity::High => 128,
    };

    let data = crate::primitives::security::generate_secure_random_bytes(size).map_err(|e| {
        CoreError::EntropyDepleted {
            message: format!("Failed to generate challenge: {e}"),
            action: "Check system entropy source".to_string(),
        }
    })?;
    // Challenge data is sent over the wire and is not secret material; the
    // ephemeral `Zeroizing` wrapper is dropped (and the source bytes wiped)
    // when this function returns.
    Ok(data.to_vec())
}

impl ZeroTrustAuth {
    /// Compute proof data using Ed25519 signature-based challenge-response.
    ///
    /// This is a proper zero-knowledge proof: the signature proves knowledge
    /// of the private key without revealing any information about it.
    ///
    /// Proof complexity affects what is signed:
    /// - Low: sign(challenge)
    /// - Medium: sign(challenge || timestamp)
    /// - High: sign(challenge || timestamp || context)
    pub(super) fn compute_proof_data(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let timestamp = Utc::now().timestamp_millis().to_le_bytes();

        // All complexity levels bind the timestamp into the signed
        // message so the verifier can enforce a freshness window. The
        // previous Low variant signed only `challenge`, making
        // `(challenge, signature)` pairs replayable indefinitely
        // until session expiry. Replay
        // protection is no longer opt-in.
        // Every variant binds the public key into the signed transcript
        // so a verifier holding pk can be sure the proof was produced
        // *for that pk* and not relayed from a session under a different
        // identity. Without PK binding, an attacker who captured a
        // valid (challenge, signature) pair under pk_A could replay it
        // against a verifier expecting pk_B if the signature happened
        // to verify under pk_B too (catastrophic if a verifier holds
        // multiple registered keys). The 1-byte domain tag separates
        // the three complexity levels so a Low proof cannot satisfy a
        // Medium or High verifier and vice versa.
        let message_to_sign = match self.config.proof_complexity {
            ProofComplexity::Low => {
                let mut msg = vec![0x01];
                msg.extend_from_slice(challenge);
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
            ProofComplexity::Medium => {
                let mut msg = vec![0x02];
                msg.extend_from_slice(challenge);
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
            ProofComplexity::High => {
                let mut msg = vec![0x03];
                msg.extend_from_slice(challenge);
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
        };

        // Sign the message - this IS zero-knowledge
        // The signature proves knowledge of private key without revealing it
        //
        // M-A: bind ZK-proof signatures to a ZK-proof-specific Ed25519
        // context. The internal 0x01/0x02/0x03 complexity tags inside
        // `message_to_sign` keep Low/Medium/High distinguishable within
        // this protocol; the SHA-512 prefix-padded context here keeps a
        // captured ZK proof from replaying as a SignedData or PoP signed
        // by the same Ed25519 key. Mirrors the post-M-A pure-Ed25519
        // construction and the hybrid leg.
        use crate::types::domains::{hash_with_context, zk_proof_sig_context};
        let zk_digest = hash_with_context(zk_proof_sig_context(), &message_to_sign);

        let signature = crate::unified_api::convenience::ed25519::sign_ed25519_internal(
            &zk_digest,
            self.private_key.expose_secret(),
        )?;

        // Append the timestamp to the proof bytes so the verifier can
        // recover it. All three complexity levels now carry a timestamp
        // suffix; older proofs without the
        // suffix will fail length check at verify time.
        let mut proof = signature;
        proof.extend_from_slice(&timestamp);
        Ok(proof)
    }

    /// Verify proof using PUBLIC KEY only.
    ///
    /// This is the correct way to verify a zero-knowledge proof:
    /// only the public key is needed, not the private key.
    pub(super) fn verify_proof_data(&self, proof: &[u8], challenge: &[u8]) -> Result<bool> {
        // Ed25519 signatures are 64 bytes
        if proof.len() < 64 {
            return Ok(false);
        }

        match self.config.proof_complexity {
            ProofComplexity::Low => {
                // Low now requires the
                // 8-byte timestamp suffix (mandatory replay protection).
                if proof.len() < 72 {
                    return Ok(false);
                }
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // verify signature BEFORE applying the
                // freshness check. The original ordering parsed the
                // timestamp out of `proof[64..72]` and ran the 30-s/
                // 5-min checks on raw adversary-supplied bytes; even
                // though signature verification would still catch a
                // tampered timestamp downstream, the principle
                // "authenticate before acting on adversary content"
                // wants verify first. Mirrored across Medium / High
                // branches below.
                let mut message = vec![0x01];
                message.extend_from_slice(challenge);
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());
                // M-A: mirror generate_proof_data's
                // SHA-512(zk_ctx || 0x00 || message) construction.
                use crate::types::domains::{hash_with_context, zk_proof_sig_context};
                let zk_digest = hash_with_context(zk_proof_sig_context(), &message);
                let sig_ok = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
                    &zk_digest,
                    signature,
                    self.public_key.as_slice(),
                )?;
                if !sig_ok {
                    return Ok(false);
                }

                // Timestamp is now authenticated — freshness check is
                // safe to run on `timestamp_bytes`.
                let proof_ts_ms = i64::from_le_bytes(timestamp_bytes);
                let now_ms = Utc::now().timestamp_millis();
                // tighten the future-skew cap
                // to match the sibling `verify_pop` path. `abs_diff(...)
                // > 300_000` accepted proofs up to 5 min in the future,
                // which gives an attacker with a forward-skewed clock a
                // 10-min replay window. Reject anything more than 30 s
                // ahead of "now"; the 5-min window only applies to the
                // past direction.
                if proof_ts_ms > now_ms.saturating_add(30_000) {
                    tracing::warn!(
                        proof_ts_ms,
                        now_ms,
                        "proof timestamp more than 30 s in the future"
                    );
                    return Ok(false);
                }
                let drift_ms = now_ms.abs_diff(proof_ts_ms);
                if drift_ms > 300_000 {
                    tracing::warn!(drift_ms, "proof timestamp outside 5-min freshness window");
                    return Ok(false);
                }

                Ok(true)
            }
            ProofComplexity::Medium => {
                // Extract signature and timestamp
                if proof.len() < 72 {
                    return Ok(false);
                }
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // verify before freshness (mirrors Low).
                // Reconstruct signed message. The 0x02 domain tag
                // distinguishes Medium from Low/High; the public-key
                // suffix binds the signature to this specific
                // verifier identity (HPKE-style channel binding).
                let mut message = vec![0x02];
                message.extend_from_slice(challenge);
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());
                // M-A: mirror generate_proof_data's
                // SHA-512(zk_ctx || 0x00 || message) construction.
                use crate::types::domains::{hash_with_context, zk_proof_sig_context};
                let zk_digest = hash_with_context(zk_proof_sig_context(), &message);
                let sig_ok = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
                    &zk_digest,
                    signature,
                    self.public_key.as_slice(),
                )?;
                if !sig_ok {
                    return Ok(false);
                }

                // Reject stale proofs (>5 min drift).
                // Timestamp is encoded as chrono milliseconds in little-endian.
                let proof_ts_ms = i64::from_le_bytes(timestamp_bytes);
                let now_ms = Utc::now().timestamp_millis();
                // tighten the future-skew cap
                // to match the sibling `verify_pop` path. `abs_diff(...)
                // > 300_000` accepted proofs up to 5 min in the future,
                // which gives an attacker with a forward-skewed clock a
                // 10-min replay window. Reject anything more than 30 s
                // ahead of "now"; the 5-min window only applies to the
                // past direction.
                if proof_ts_ms > now_ms.saturating_add(30_000) {
                    tracing::warn!(
                        proof_ts_ms,
                        now_ms,
                        "proof timestamp more than 30 s in the future"
                    );
                    return Ok(false);
                }
                let drift_ms = now_ms.abs_diff(proof_ts_ms);
                if drift_ms > 300_000 {
                    tracing::warn!(drift_ms, "proof timestamp outside 5-min freshness window");
                    return Ok(false);
                }

                Ok(true)
            }
            ProofComplexity::High => {
                // Extract signature and timestamp
                if proof.len() < 72 {
                    return Ok(false);
                }
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // verify before freshness (mirrors Low).
                // Reconstruct signed message with public key binding.
                // High prepends a 0x03 domain
                // tag so it is byte-distinguishable from both Low and
                // Medium.
                let mut message = vec![0x03];
                message.extend_from_slice(challenge);
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());
                // M-A: mirror generate_proof_data's
                // SHA-512(zk_ctx || 0x00 || message) construction.
                use crate::types::domains::{hash_with_context, zk_proof_sig_context};
                let zk_digest = hash_with_context(zk_proof_sig_context(), &message);
                let sig_ok = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
                    &zk_digest,
                    signature,
                    self.public_key.as_slice(),
                )?;
                if !sig_ok {
                    return Ok(false);
                }

                // Reject stale proofs (>5 min drift).
                // Timestamp is encoded as chrono milliseconds in little-endian.
                let proof_ts_ms = i64::from_le_bytes(timestamp_bytes);
                let now_ms = Utc::now().timestamp_millis();
                // tighten the future-skew cap
                // to match the sibling `verify_pop` path. `abs_diff(...)
                // > 300_000` accepted proofs up to 5 min in the future,
                // which gives an attacker with a forward-skewed clock a
                // 10-min replay window. Reject anything more than 30 s
                // ahead of "now"; the 5-min window only applies to the
                // past direction.
                if proof_ts_ms > now_ms.saturating_add(30_000) {
                    tracing::warn!(
                        proof_ts_ms,
                        now_ms,
                        "proof timestamp more than 30 s in the future"
                    );
                    return Ok(false);
                }
                let drift_ms = now_ms.abs_diff(proof_ts_ms);
                if drift_ms > 300_000 {
                    tracing::warn!(drift_ms, "proof timestamp outside 5-min freshness window");
                    return Ok(false);
                }

                Ok(true)
            }
        }
    }
}
