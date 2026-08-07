//! `KeyType`: the public/secret/symmetric key-role classifier.

use serde::{Deserialize, Serialize};

// ============================================================================
// KeyType
// ============================================================================

/// Key type classifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// Public key (safe to share).
    Public,
    /// Secret (private) key — MUST be protected.
    Secret,
    /// Symmetric key — MUST be protected.
    Symmetric,
}

impl KeyType {
    /// Canonical wire name for this key type — matches the serde
    /// `rename_all = "lowercase"` output. Load-bearing for encrypted
    /// key files; see [`KeyAlgorithm::canonical_name`](super::KeyAlgorithm::canonical_name).
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Secret => "secret",
            Self::Symmetric => "symmetric",
        }
    }
}
