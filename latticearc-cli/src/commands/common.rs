//! Shared CLI types for use-case-driven operations.
//!
//! Maps CLI string values directly to library enums — no wrapper types.
//! The library's `UseCase`, `SecurityLevel`, and `ComplianceMode` are used
//! directly in clap args via custom `value_parser` functions.

use latticearc::types::types::{ComplianceMode, SecurityLevel, UseCase};

/// All valid use case CLI values. Single source of truth for help text and parsing.
const USE_CASES: &[(&str, UseCase)] = &[
    ("secure-messaging", UseCase::SecureMessaging),
    ("email-encryption", UseCase::EmailEncryption),
    ("vpn-tunnel", UseCase::VpnTunnel),
    ("api-security", UseCase::ApiSecurity),
    ("file-storage", UseCase::FileStorage),
    ("database-encryption", UseCase::DatabaseEncryption),
    ("cloud-storage", UseCase::CloudStorage),
    ("backup-archive", UseCase::BackupArchive),
    ("config-secrets", UseCase::ConfigSecrets),
    ("authentication", UseCase::Authentication),
    ("session-token", UseCase::SessionToken),
    ("digital-certificate", UseCase::DigitalCertificate),
    ("key-exchange", UseCase::KeyExchange),
    ("financial-transactions", UseCase::FinancialTransactions),
    ("legal-documents", UseCase::LegalDocuments),
    ("blockchain-transaction", UseCase::BlockchainTransaction),
    ("healthcare-records", UseCase::HealthcareRecords),
    ("government-classified", UseCase::GovernmentClassified),
    ("payment-card", UseCase::PaymentCard),
    ("iot-device", UseCase::IoTDevice),
    ("firmware-signing", UseCase::FirmwareSigning),
    ("audit-log", UseCase::AuditLog),
];

const SECURITY_LEVELS: &[(&str, SecurityLevel)] = &[
    ("standard", SecurityLevel::Standard),
    ("high", SecurityLevel::High),
    ("maximum", SecurityLevel::Maximum),
    ("quantum", SecurityLevel::Quantum),
];

const COMPLIANCE_MODES: &[(&str, ComplianceMode)] = &[
    ("default", ComplianceMode::Default),
    ("fips", ComplianceMode::Fips140_3),
    ("cnsa-2.0", ComplianceMode::Cnsa2_0),
];

/// Parse a use case from a CLI string.
pub(crate) fn parse_use_case(s: &str) -> Result<UseCase, String> {
    USE_CASES.iter().find(|(name, _)| *name == s).map(|(_, uc)| *uc).ok_or_else(|| {
        let valid: Vec<&str> = USE_CASES.iter().map(|(n, _)| *n).collect();
        format!("Unknown use case '{s}'. Valid values:\n  {}", valid.join(", "))
    })
}

/// Parse a security level from a CLI string.
pub(crate) fn parse_security_level(s: &str) -> Result<SecurityLevel, String> {
    SECURITY_LEVELS.iter().find(|(name, _)| *name == s).map(|(_, sl)| *sl).ok_or_else(|| {
        let valid: Vec<&str> = SECURITY_LEVELS.iter().map(|(n, _)| *n).collect();
        format!("Unknown security level '{s}'. Valid: {}", valid.join(", "))
    })
}

/// Parse a compliance mode from a CLI string.
pub(crate) fn parse_compliance(s: &str) -> Result<ComplianceMode, String> {
    COMPLIANCE_MODES.iter().find(|(name, _)| *name == s).map(|(_, cm)| cm.clone()).ok_or_else(
        || {
            let valid: Vec<&str> = COMPLIANCE_MODES.iter().map(|(n, _)| *n).collect();
            format!("Unknown compliance mode '{s}'. Valid: {}", valid.join(", "))
        },
    )
}

/// Build a `CryptoConfig` from optional CLI values.
pub(crate) fn build_config<'a>(
    use_case: Option<UseCase>,
    security_level: Option<SecurityLevel>,
    compliance: &Option<ComplianceMode>,
) -> latticearc::CryptoConfig<'a> {
    let mut config = latticearc::CryptoConfig::new();

    if let Some(uc) = use_case {
        config = config.use_case(uc);
    }

    if let Some(sl) = security_level {
        config = config.security_level(sl);
    }

    if let Some(cm) = compliance {
        config = config.compliance(cm.clone());
    }

    config
}
