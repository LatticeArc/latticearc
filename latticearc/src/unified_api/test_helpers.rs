//! Shared test helpers for the `unified_api` test modules.
//!
//! Lives behind `#[cfg(test)]` so it is excluded from production builds and
//! does not appear in rustdoc. Visible to both `unified_api/tests.rs` and
//! `unified_api/convenience/*::tests` because it is declared `pub(crate)`.

use crate::types::types::{ComplianceMode, UseCase};
use crate::unified_api::CryptoConfig;

/// Construct a `CryptoConfig` for `use_case` with the per-use-case default
/// compliance overridden to `ComplianceMode::Default`.
///
/// Required so tests that exercise FIPS-defaulted use cases
/// (`FinancialTransactions`, `HealthcareRecords`, `GovernmentClassified`,
/// `PaymentCard`) compile and run under `--no-default-features` —
/// `validate()` would otherwise reject the auto-set `Fips140_3` compliance
/// with `FeatureNotAvailable`. FIPS-mode behaviour for these use cases is
/// covered by the dedicated `test_fips_*` tests in `convenience/api.rs`.
///
/// The lifetime `'a` is unconstrained — caller picks; the returned config
/// carries no session reference.
pub(crate) fn non_fips_config<'a>(use_case: UseCase) -> CryptoConfig<'a> {
    CryptoConfig::new().use_case(use_case).compliance(ComplianceMode::Default)
}
