//! The single error type that crosses the FFI boundary.
//!
//! Every fallible call returns `Result<T, LatticeArcError>`, which UniFFI
//! turns into a thrown Swift error / Kotlin exception with one case per
//! variant. Failures an attacker can trigger with forged data (wrong key,
//! tampered ciphertext, bad signature) collapse into the reason-free
//! [`LatticeArcError::AuthenticationFailed`], matching the opaque-error
//! policy of the core crate; every other variant carries a `reason` meant
//! for logs, never for the user interface.

use latticearc::hybrid::encrypt_hybrid::HybridEncryptionError;
use latticearc::hybrid::kem_hybrid::HybridKemError;
use latticearc::hybrid::sig_hybrid::HybridSignatureError;
use latticearc::hybrid::wire::WireError;
use latticearc::prelude::LatticeArcError as CoreError;
use latticearc::primitives::aead::AeadError;
use latticearc::primitives::sig::ml_dsa::MlDsaError;

/// Errors raised by the LatticeArc FFI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum LatticeArcError {
    /// An argument had the wrong length, encoding or value.
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// What was wrong with the argument.
        reason: String,
    },
    /// A domain-separation context was empty or too long.
    #[error("invalid context: {reason}")]
    InvalidContext {
        /// What was wrong with the context.
        reason: String,
    },
    /// Argon2 or other algorithm parameters were outside the allowed range.
    #[error("invalid parameters: {reason}")]
    InvalidParams {
        /// Which parameter was rejected and why.
        reason: String,
    },
    /// The call would exceed a configured resource limit (for example the
    /// Argon2 memory cap).
    #[error("resource limit exceeded: {reason}")]
    ResourceLimit {
        /// Which limit was hit.
        reason: String,
    },
    /// Decryption, unwrapping, decapsulation or verification failed. The
    /// reason is deliberately not reported.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// A streaming encryptor or decryptor was used after `finish` / the
    /// last segment, or its segment counter ran out.
    #[error("stream exhausted")]
    StreamExhausted,
    /// Bytes did not parse as the LatticeArc wire format.
    #[error("wire format: {reason}")]
    WireFormat {
        /// Which check failed.
        reason: String,
    },
    /// Key generation failed.
    #[error("key generation failed: {reason}")]
    KeyGeneration {
        /// The underlying failure.
        reason: String,
    },
    /// An unexpected failure inside the library.
    #[error("internal error: {reason}")]
    Internal {
        /// The underlying failure.
        reason: String,
    },
}

impl LatticeArcError {
    pub(crate) fn invalid_input(reason: impl Into<String>) -> Self {
        Self::InvalidInput { reason: reason.into() }
    }

    pub(crate) fn internal(reason: impl Into<String>) -> Self {
        Self::Internal { reason: reason.into() }
    }
}

impl From<AeadError> for LatticeArcError {
    fn from(e: AeadError) -> Self {
        match e {
            AeadError::DecryptionFailed(_) => Self::AuthenticationFailed,
            AeadError::StreamExhausted | AeadError::SegmentCounterExhausted => {
                Self::StreamExhausted
            }
            AeadError::EmptyContext => Self::InvalidContext { reason: e.to_string() },
            AeadError::EncryptionFailed(_) => Self::Internal { reason: e.to_string() },
            AeadError::InvalidKeyLength
            | AeadError::InvalidNonceLength
            | AeadError::WeakKey
            | AeadError::InvalidSegmentSize
            | AeadError::InvalidSegmentLength
            | AeadError::InvalidPaddedLength
            | AeadError::MalformedEncoding => Self::InvalidInput { reason: e.to_string() },
            _ => Self::Internal { reason: e.to_string() },
        }
    }
}

impl From<CoreError> for LatticeArcError {
    fn from(e: CoreError) -> Self {
        let reason = e.to_string();
        match e {
            CoreError::InvalidParameter(_) | CoreError::InvalidConfiguration(_) => {
                Self::InvalidParams { reason }
            }
            CoreError::InvalidInput(_)
            | CoreError::InvalidData(_)
            | CoreError::InvalidKey(_)
            | CoreError::InvalidKeyLength { .. }
            | CoreError::InvalidSignatureLength { .. }
            | CoreError::ValidationError { .. }
            | CoreError::MessageTooLong
            | CoreError::DeserializationError(_) => Self::InvalidInput { reason },
            CoreError::ResourceExhausted | CoreError::MemoryError(_) => {
                Self::ResourceLimit { reason }
            }
            CoreError::KeyGenerationError(_) => Self::KeyGeneration { reason },
            CoreError::AuthenticationError(_)
            | CoreError::DecryptionError(_)
            | CoreError::DecapsulationError(_)
            | CoreError::InvalidSignature(_)
            | CoreError::SignatureVerificationError(_)
            | CoreError::VerificationFailed(_) => Self::AuthenticationFailed,
            _ => Self::Internal { reason },
        }
    }
}

impl From<HybridKemError> for LatticeArcError {
    fn from(e: HybridKemError) -> Self {
        let reason = e.to_string();
        match e {
            HybridKemError::DecapsulationFailed => Self::AuthenticationFailed,
            HybridKemError::InvalidContext(_) => Self::InvalidContext { reason },
            HybridKemError::InvalidKeyMaterial(_) => Self::InvalidInput { reason },
            HybridKemError::EncapsulationFailed
            | HybridKemError::MlKemError(_)
            | HybridKemError::EcdhError(_)
            | HybridKemError::KdfError(_)
            | HybridKemError::CryptoError(_) => Self::Internal { reason },
            // The core enum is `#[non_exhaustive]`: a variant added later is
            // surfaced as `Internal`, never as a caller mistake.
            _ => Self::Internal { reason },
        }
    }
}

impl From<HybridSignatureError> for LatticeArcError {
    fn from(e: HybridSignatureError) -> Self {
        let reason = e.to_string();
        match e {
            HybridSignatureError::VerificationFailed(_) => Self::AuthenticationFailed,
            HybridSignatureError::InvalidContext(_) => Self::InvalidContext { reason },
            HybridSignatureError::InvalidKeyMaterial(_)
            | HybridSignatureError::InvalidDigestLength { .. } => Self::InvalidInput { reason },
            HybridSignatureError::MlDsaError(_)
            | HybridSignatureError::Ed25519Error(_)
            | HybridSignatureError::SigningFailed(_)
            | HybridSignatureError::CryptoError(_) => Self::Internal { reason },
            _ => Self::Internal { reason },
        }
    }
}

impl From<HybridEncryptionError> for LatticeArcError {
    fn from(e: HybridEncryptionError) -> Self {
        let reason = e.to_string();
        match e {
            HybridEncryptionError::DecryptionError(_) => Self::AuthenticationFailed,
            HybridEncryptionError::InvalidInput(_)
            | HybridEncryptionError::KeyLengthError { .. } => Self::InvalidInput { reason },
            HybridEncryptionError::KemError(_)
            | HybridEncryptionError::EncryptionError(_)
            | HybridEncryptionError::KdfError(_) => Self::Internal { reason },
            _ => Self::Internal { reason },
        }
    }
}

impl From<WireError> for LatticeArcError {
    fn from(e: WireError) -> Self {
        Self::WireFormat { reason: e.to_string() }
    }
}

impl From<MlDsaError> for LatticeArcError {
    fn from(e: MlDsaError) -> Self {
        let reason = e.to_string();
        match e {
            MlDsaError::VerificationError(_) => Self::AuthenticationFailed,
            MlDsaError::KeyGenerationError(_) => Self::KeyGeneration { reason },
            MlDsaError::SigningError(_) | MlDsaError::CryptoError(_) => Self::Internal { reason },
            MlDsaError::InvalidKeyLength { .. }
            | MlDsaError::InvalidSignatureLength { .. }
            | MlDsaError::InvalidParameterSet(_)
            | MlDsaError::ParameterSetMismatch { .. } => Self::InvalidInput { reason },
            _ => Self::Internal { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_failures_are_opaque() {
        let e: LatticeArcError = AeadError::DecryptionFailed("inner detail".to_string()).into();
        assert_eq!(e, LatticeArcError::AuthenticationFailed);
        assert_eq!(e.to_string(), "authentication failed");
    }

    #[test]
    fn empty_context_maps_to_invalid_context() {
        let e: LatticeArcError = AeadError::EmptyContext.into();
        assert!(matches!(e, LatticeArcError::InvalidContext { .. }));
    }

    #[test]
    fn context_variants_route_to_invalid_context_and_the_rest_to_internal() {
        let e: LatticeArcError = HybridKemError::InvalidContext("empty".to_string()).into();
        assert!(matches!(e, LatticeArcError::InvalidContext { .. }));
        let e: LatticeArcError = HybridKemError::EncapsulationFailed.into();
        assert!(matches!(e, LatticeArcError::Internal { .. }));
        let e: LatticeArcError = HybridSignatureError::InvalidContext("long".to_string()).into();
        assert!(matches!(e, LatticeArcError::InvalidContext { .. }));
        let e: LatticeArcError = MlDsaError::InvalidParameterSet("x".to_string()).into();
        assert!(matches!(e, LatticeArcError::InvalidInput { .. }));
    }

    #[test]
    fn wire_errors_keep_their_message() {
        let e: LatticeArcError = WireError::Truncated.into();
        assert!(
            matches!(e, LatticeArcError::WireFormat { ref reason } if !reason.is_empty()),
            "{e:?}"
        );
    }
}
