//! FIPS validation types and data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// FIPS validation scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationScope {
    /// Validate individual algorithms only
    AlgorithmsOnly,
    /// Validate cryptographic module interfaces
    ModuleInterfaces,
    /// Full module validation (algorithms + interfaces + security policy)
    FullModule,
}

/// FIPS security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FIPSLevel {
    /// Level 1: Basic security
    Level1,
    /// Level 2: Tamper-evident
    Level2,
    /// Level 3: Tamper-resistant
    Level3,
    /// Level 4: Highest security (tamper-resistant + environmental failure protection)
    Level4,
}

/// Validation issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    /// Critical issue preventing FIPS compliance
    Critical,
    /// High severity issue
    High,
    /// Medium severity issue
    Medium,
    /// Low severity issue
    Low,
    /// Informational note
    Info,
}

/// Individual validation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Issue identifier
    pub id: String,
    /// Issue description
    pub description: String,
    /// FIPS requirement reference
    pub requirement_ref: String,
    /// Issue severity
    pub severity: IssueSeverity,
    /// Affected component
    pub affected_component: String,
    /// Remediation guidance
    pub remediation: String,
    /// Evidence or test case that revealed the issue
    pub evidence: String,
}

/// FIPS validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Validation run identifier
    pub validation_id: String,
    /// Validation timestamp
    pub timestamp: DateTime<Utc>,
    /// Validation scope used
    pub scope: ValidationScope,
    /// Overall validation status
    pub is_valid: bool,
    /// Achieved FIPS security level
    pub level: Option<FIPSLevel>,
    /// Validation issues found
    pub issues: Vec<ValidationIssue>,
    /// Test results for individual requirements
    pub test_results: HashMap<String, TestResult>,
    /// Validation metadata
    pub metadata: HashMap<String, String>,
}

/// Individual test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test identifier
    pub test_id: String,
    /// Test passed
    pub passed: bool,
    /// Test duration in milliseconds
    pub duration_ms: u64,
    /// Test output or evidence
    pub output: String,
    /// Error message if test failed
    pub error_message: Option<String>,
}

/// FIPS validation certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCertificate {
    /// Certificate identifier
    pub id: String,
    /// Module name
    pub module_name: String,
    /// Module version
    pub module_version: String,
    /// FIPS security level
    pub security_level: FIPSLevel,
    /// Validation date
    pub validation_date: DateTime<Utc>,
    /// Certificate expiry date
    pub expiry_date: DateTime<Utc>,
    /// Validation lab identifier
    pub lab_id: String,
    /// Certificate details
    pub details: HashMap<String, String>,
}

impl ValidationResult {
    /// Check if validation passed
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get issues by severity
    #[must_use]
    pub fn issues_by_severity(&self, severity: IssueSeverity) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|i| i.severity == severity).collect()
    }

    /// Get critical issues
    #[must_use]
    pub fn critical_issues(&self) -> Vec<&ValidationIssue> {
        self.issues_by_severity(IssueSeverity::Critical)
    }
}
