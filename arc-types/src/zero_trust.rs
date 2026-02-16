//! Pure-Rust zero-trust types.
//!
//! Contains the `TrustLevel` enum which has no FFI dependencies.
//! The rest of the zero-trust module (sessions, challenges, proofs)
//! remains in `arc-core` due to Ed25519 FFI dependencies.

/// Trust level for zero-trust sessions.
///
/// Represents the current level of trust established through
/// challenge-response verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum TrustLevel {
    /// No trust established - initial state before any verification.
    #[default]
    Untrusted = 0,
    /// Partial trust - first verification has passed.
    Partial = 1,
    /// Trusted - multiple verifications have passed.
    Trusted = 2,
    /// Fully trusted - continuous verification is active and passing.
    FullyTrusted = 3,
}

impl TrustLevel {
    /// Returns `true` if at least partial trust has been established.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        *self >= Self::Partial
    }

    /// Returns `true` if full trust has been established.
    #[must_use]
    pub fn is_fully_trusted(&self) -> bool {
        *self == Self::FullyTrusted
    }
}

// Formal verification with Kani
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proves that TrustLevel ordering is total: for any two levels,
    /// exactly one of <, ==, > holds. This ensures the trust hierarchy
    /// has no ambiguous comparisons.
    #[kani::proof]
    fn trust_level_ordering_total() {
        let a: TrustLevel = kani::any();
        let b: TrustLevel = kani::any();

        let less = a < b;
        let equal = a == b;
        let greater = a > b;

        // Exactly one must hold (XOR logic via sum)
        let count = less as u8 + equal as u8 + greater as u8;
        kani::assert!(count == 1, "TrustLevel ordering must be total");
    }

    /// Proves that `is_trusted()` returns true if and only if the level
    /// is at least Partial. Security property: Untrusted entities are
    /// never considered trusted.
    #[kani::proof]
    fn trust_level_is_trusted_iff_at_least_partial() {
        let level: TrustLevel = kani::any();

        let trusted = level.is_trusted();
        let at_least_partial = level >= TrustLevel::Partial;

        kani::assert!(
            trusted == at_least_partial,
            "is_trusted() must be true iff level >= Partial"
        );
    }

    /// Proves that Untrusted is the minimum trust level — no level
    /// is lower. Security property: the trust floor is well-defined.
    #[kani::proof]
    fn trust_level_untrusted_is_minimum() {
        let level: TrustLevel = kani::any();

        kani::assert!(TrustLevel::Untrusted <= level, "Untrusted must be the minimum trust level");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_default() {
        assert_eq!(TrustLevel::default(), TrustLevel::Untrusted);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Untrusted < TrustLevel::Partial);
        assert!(TrustLevel::Partial < TrustLevel::Trusted);
        assert!(TrustLevel::Trusted < TrustLevel::FullyTrusted);
    }

    #[test]
    fn test_trust_level_is_trusted() {
        assert!(!TrustLevel::Untrusted.is_trusted());
        assert!(TrustLevel::Partial.is_trusted());
        assert!(TrustLevel::Trusted.is_trusted());
        assert!(TrustLevel::FullyTrusted.is_trusted());
    }

    #[test]
    fn test_trust_level_is_fully_trusted() {
        assert!(!TrustLevel::Untrusted.is_fully_trusted());
        assert!(!TrustLevel::Partial.is_fully_trusted());
        assert!(!TrustLevel::Trusted.is_fully_trusted());
        assert!(TrustLevel::FullyTrusted.is_fully_trusted());
    }
}
