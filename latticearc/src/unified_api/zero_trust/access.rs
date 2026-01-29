#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Access control for zero-trust authentication.
//!
//! This module provides access control policies, rules, conditions, and decisions
//! for enforcing zero-trust security at the cryptographic operation level.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::unified_api::error::CryptoError;

use super::{primitives::TrustLevel, session::ZeroTrustSession};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessAction {
    Allow,
    Deny,
    RequireMFA,
    RequireReverification,
    RequireElevatedTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone)]
pub enum AccessCondition {
    Always,
    Never,
    TrustLevelRequired(TrustLevel),
    TimeBased(TimeWindow),
    LocationBased(Vec<String>),
    MFARequired(bool),
    DIDRequired(bool),
    Composite { operator: LogicalOperator, conditions: Vec<AccessCondition> },
}

#[derive(Debug, Clone)]
pub struct TimeWindow {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub timezone: String,
}

impl TimeWindow {
    pub fn new(start_time: DateTime<Utc>, end_time: DateTime<Utc>, timezone: String) -> Self {
        Self { start_time, end_time, timezone }
    }

    pub fn is_active(&self) -> bool {
        let now = Utc::now();

        match now.duration_since(self.start_time) {
            Ok(_duration_since_start) => match self.end_time.duration_since(now) {
                Ok(duration_until_end) => duration_until_end.as_millis() > 0,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessRule {
    pub rule_id: String,
    pub name: String,
    pub priority: u32,
    pub condition: AccessCondition,
    pub action: AccessAction,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl AccessRule {
    pub fn new(
        rule_id: String,
        name: String,
        priority: u32,
        condition: AccessCondition,
        action: AccessAction,
    ) -> Self {
        Self {
            rule_id,
            name,
            priority,
            condition,
            action,
            description: String::new(),
            created_at: DateTime::<Utc>::now(),
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    pub fn evaluate(&self, session: &ZeroTrustSession) -> Result<bool, CryptoError> {
        self.evaluate_condition(&self.condition, session)
    }

    fn evaluate_condition(
        &self,
        condition: &AccessCondition,
        session: &ZeroTrustSession,
    ) -> Result<bool, CryptoError> {
        match condition {
            AccessCondition::Always => Ok(true),
            AccessCondition::Never => Ok(false),
            AccessCondition::TrustLevelRequired(level) => Ok(session.trust_level >= *level),
            AccessCondition::TimeBased(window) => Ok(window.is_active()),
            AccessCondition::LocationBased(allowed_locations) => {
                if let Some(ref location) = session.security_context.location {
                    Ok(location.matches(allowed_locations))
                } else {
                    Ok(false)
                }
            }
            AccessCondition::MFARequired(required) => {
                if *required {
                    Ok(session.trust_level >= TrustLevel::Medium)
                } else {
                    Ok(true)
                }
            }
            AccessCondition::DIDRequired(required) => Ok(match required {
                true => session.did.is_some(),
                false => true,
            }),
            AccessCondition::Composite { operator, conditions } => match operator {
                LogicalOperator::And => {
                    for cond in conditions {
                        if !self.evaluate_condition(cond, session)? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                LogicalOperator::Or => {
                    for cond in conditions {
                        if self.evaluate_condition(cond, session)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                LogicalOperator::Not => {
                    if conditions.len() != 1 {
                        return Err(CryptoError::InvalidInput(
                            "NOT condition requires exactly one sub-condition".to_string(),
                        ));
                    }
                    Ok(!self.evaluate_condition(&conditions[0], session)?)
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub policy_id: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<AccessRule>,
    pub default_action: AccessAction,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AccessPolicy {
    pub fn new(policy_id: String, name: String, default_action: AccessAction) -> Self {
        let now = Utc::now();
        Self {
            policy_id,
            name,
            description: String::new(),
            rules: Vec::new(),
            default_action,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    pub fn with_rules(mut self, rules: Vec<AccessRule>) -> Self {
        self.rules = rules;
        self.updated_at = Utc::now();
        self
    }

    pub fn add_rule(&mut self, rule: AccessRule) {
        self.rules.push(rule);
        self.updated_at = Utc::now();
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> Result<(), CryptoError> {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        self.updated_at = Utc::now();

        if self.rules.len() == len_before {
            return Err(CryptoError::InvalidInput(format!("Rule '{}' not found", rule_id)));
        }

        Ok(())
    }

    pub fn get_rule(&self, rule_id: &str) -> Option<&AccessRule> {
        self.rules.iter().find(|r| r.rule_id == rule_id)
    }

    /// Evaluate the access policy for the given session.
    ///
    /// Evaluates rules in priority order (highest first) and returns the first
    /// matching rule's action, or the default action if no rules match.
    ///
    /// # Errors
    ///
    /// Returns an error if rule evaluation fails (e.g., invalid NOT condition).
    pub fn evaluate(&self, session: &ZeroTrustSession) -> Result<AccessDecision, CryptoError> {
        let sorted_rules = {
            let mut rules = self.rules.clone();
            rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
            rules
        };

        for rule in &sorted_rules {
            if rule.evaluate(session)? {
                let allowed = matches!(rule.action, AccessAction::Allow);
                let reason = format!("Matched rule '{}'", rule.name);

                // Log the access decision
                if allowed {
                    tracing::info!(
                        target: "zero_trust::access",
                        session_id = %session.session_id,
                        policy_id = %self.policy_id,
                        rule_id = %rule.rule_id,
                        allowed = allowed,
                        reason = %reason,
                        "Zero Trust access granted"
                    );
                } else {
                    tracing::warn!(
                        target: "zero_trust::access",
                        session_id = %session.session_id,
                        policy_id = %self.policy_id,
                        rule_id = %rule.rule_id,
                        allowed = allowed,
                        action = ?rule.action,
                        reason = %reason,
                        "Zero Trust access denied"
                    );
                }

                return Ok(AccessDecision {
                    allowed,
                    action: rule.action,
                    reason,
                    timestamp: DateTime::<Utc>::now(),
                });
            }
        }

        let allowed = matches!(self.default_action, AccessAction::Allow);
        let reason = "No rules matched, using default action".to_string();

        // Log default action decision
        if allowed {
            tracing::info!(
                target: "zero_trust::access",
                session_id = %session.session_id,
                policy_id = %self.policy_id,
                allowed = allowed,
                reason = %reason,
                "Zero Trust access granted (default)"
            );
        } else {
            tracing::warn!(
                target: "zero_trust::access",
                session_id = %session.session_id,
                policy_id = %self.policy_id,
                allowed = allowed,
                action = ?self.default_action,
                reason = %reason,
                "Zero Trust access denied (default)"
            );
        }

        Ok(AccessDecision {
            allowed,
            action: self.default_action,
            reason,
            timestamp: DateTime::<Utc>::now(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AccessDecision {
    pub allowed: bool,
    pub action: AccessAction,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

impl AccessDecision {
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }

    pub fn requires_action(&self) -> bool {
        matches!(
            self.action,
            AccessAction::RequireMFA
                | AccessAction::RequireReverification
                | AccessAction::RequireElevatedTrust
        )
    }
}

pub struct AccessControl {
    policies: Arc<RwLock<HashMap<String, AccessPolicy>>>,
}

impl AccessControl {
    pub fn new() -> Self {
        Self { policies: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub fn create_policy(&self, policy: AccessPolicy) -> Result<(), CryptoError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn update_policy(&self, policy_id: &str, policy: AccessPolicy) -> Result<(), CryptoError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        if !policies.contains_key(policy_id) {
            return Err(CryptoError::InvalidInput("Policy not found".to_string()));
        }

        policies.insert(policy_id.to_string(), policy);
        Ok(())
    }

    pub fn delete_policy(&self, policy_id: &str) -> Result<(), CryptoError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match policies.remove(policy_id) {
            Some(_) => Ok(()),
            None => Err(CryptoError::InvalidInput("Policy not found".to_string())),
        }
    }

    /// Get an access policy by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy is not found.
    pub fn get_policy(&self, policy_id: &str) -> Result<AccessPolicy, CryptoError> {
        let policies = self
            .policies
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match policies.get(policy_id) {
            Some(policy) => Ok(policy.clone()),
            None => {
                tracing::warn!(
                    target: "zero_trust::access",
                    policy_id = %policy_id,
                    "Access policy not found"
                );
                Err(CryptoError::InvalidInput("Policy not found".to_string()))
            }
        }
    }

    /// Evaluate access for a session against a policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy is not found or evaluation fails.
    pub fn evaluate_access(
        &self,
        session: &ZeroTrustSession,
        policy_id: &str,
    ) -> Result<AccessDecision, CryptoError> {
        tracing::debug!(
            target: "zero_trust::access",
            session_id = %session.session_id,
            policy_id = %policy_id,
            "Evaluating access control"
        );
        let policy = self.get_policy(policy_id)?;
        policy.evaluate(session)
    }

    pub fn list_policies(&self) -> Result<Vec<AccessPolicy>, CryptoError> {
        let policies = self
            .policies
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        Ok(policies.values().cloned().collect())
    }

    pub fn add_rule(&self, policy_id: &str, rule: AccessRule) -> Result<(), CryptoError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match policies.get_mut(policy_id) {
            Some(policy) => {
                policy.add_rule(rule);
                Ok(())
            }
            None => Err(CryptoError::InvalidInput("Policy not found".to_string())),
        }
    }

    pub fn remove_rule(&self, policy_id: &str, rule_id: &str) -> Result<(), CryptoError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match policies.get_mut(policy_id) {
            Some(policy) => policy.remove_rule(rule_id),
            None => Err(CryptoError::InvalidInput("Policy not found".to_string())),
        }
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_policy(policy: AccessPolicy) -> Result<(), CryptoError> {
    let access_control = AccessControl::new();
    access_control.create_policy(policy)
}

pub fn evaluate_access(
    session: &ZeroTrustSession,
    policy_id: &str,
) -> Result<AccessDecision, CryptoError> {
    let access_control = AccessControl::new();
    access_control.evaluate_access(session, policy_id)
}

pub fn add_rule(policy_id: &str, rule: AccessRule) -> Result<(), CryptoError> {
    let access_control = AccessControl::new();
    access_control.add_rule(policy_id, rule)
}

pub fn remove_rule(policy_id: &str, rule_id: &str) -> Result<(), CryptoError> {
    let access_control = AccessControl::new();
    access_control.remove_rule(policy_id, rule_id)
}

pub fn update_policy(policy_id: &str, policy: AccessPolicy) -> Result<(), CryptoError> {
    let access_control = AccessControl::new();
    access_control.update_policy(policy_id, policy)
}

pub fn delete_policy(policy_id: &str) -> Result<(), CryptoError> {
    let access_control = AccessControl::new();
    access_control.delete_policy(policy_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified_api::zero_trust::primitives::{Location, SecurityContext};

    fn create_test_session() -> ZeroTrustSession {
        ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(600),
            SecurityContext::default(),
        )
        .expect("Failed to create session")
    }

    #[test]
    fn test_time_window() {
        let now = Utc::now();
        let window = TimeWindow::new(
            now,
            now.checked_add(std::time::Duration::from_secs(3600)).unwrap(),
            "UTC".to_string(),
        );

        assert!(window.is_active());

        let expired_window = TimeWindow::new(
            now - std::time::Duration::from_secs(3600),
            now - std::time::Duration::from_secs(1800),
            "UTC".to_string(),
        );

        assert!(!expired_window.is_active());
    }

    #[test]
    fn test_access_rule_trust_level() {
        let session = create_test_session();

        let rule = AccessRule::new(
            "rule-1".to_string(),
            "Test Rule".to_string(),
            1,
            AccessCondition::TrustLevelRequired(TrustLevel::Low),
            AccessAction::Allow,
        );

        assert!(rule.evaluate(&session).expect("Failed to evaluate rule"));

        let strict_rule = AccessRule::new(
            "rule-2".to_string(),
            "Strict Rule".to_string(),
            1,
            AccessCondition::TrustLevelRequired(TrustLevel::High),
            AccessAction::Deny,
        );

        assert!(!strict_rule.evaluate(&session).expect("Failed to evaluate rule"));
    }

    #[test]
    fn test_access_rule_location() {
        let mut security_context = SecurityContext::default();
        security_context.location =
            Some(Location::new("US".to_string(), "CA".to_string(), "SF".to_string()));

        let session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(600),
            security_context,
        )
        .expect("Failed to create session");

        let rule = AccessRule::new(
            "rule-1".to_string(),
            "Location Rule".to_string(),
            1,
            AccessCondition::LocationBased(vec!["US".to_string(), "CA".to_string()]),
            AccessAction::Allow,
        );

        assert!(rule.evaluate(&session).expect("Failed to evaluate rule"));

        let strict_rule = AccessRule::new(
            "rule-2".to_string(),
            "Strict Location Rule".to_string(),
            1,
            AccessCondition::LocationBased(vec!["UK".to_string()]),
            AccessAction::Deny,
        );

        assert!(!strict_rule.evaluate(&session).expect("Failed to evaluate rule"));
    }

    #[test]
    fn test_access_rule_composite() {
        let session = create_test_session();

        let and_rule = AccessRule::new(
            "rule-1".to_string(),
            "AND Rule".to_string(),
            1,
            AccessCondition::Composite {
                operator: LogicalOperator::And,
                conditions: vec![
                    AccessCondition::TrustLevelRequired(TrustLevel::Low),
                    AccessCondition::MFARequired(true),
                ],
            },
            AccessAction::Allow,
        );

        assert!(and_rule.evaluate(&session).expect("Failed to evaluate rule"));

        let or_rule = AccessRule::new(
            "rule-2".to_string(),
            "OR Rule".to_string(),
            1,
            AccessCondition::Composite {
                operator: LogicalOperator::Or,
                conditions: vec![
                    AccessCondition::TrustLevelRequired(TrustLevel::High),
                    AccessCondition::TrustLevelRequired(TrustLevel::Medium),
                ],
            },
            AccessAction::Allow,
        );

        assert!(or_rule.evaluate(&session).expect("Failed to evaluate rule"));

        let not_rule = AccessRule::new(
            "rule-3".to_string(),
            "NOT Rule".to_string(),
            1,
            AccessCondition::Composite {
                operator: LogicalOperator::Not,
                conditions: vec![AccessCondition::Never],
            },
            AccessAction::Allow,
        );

        assert!(not_rule.evaluate(&session).expect("Failed to evaluate rule"));
    }

    #[test]
    fn test_access_policy() {
        let session = create_test_session();

        let mut policy = AccessPolicy::new(
            "policy-1".to_string(),
            "Test Policy".to_string(),
            AccessAction::Deny,
        );

        let rule = AccessRule::new(
            "rule-1".to_string(),
            "Allow Rule".to_string(),
            1,
            AccessCondition::TrustLevelRequired(TrustLevel::Low),
            AccessAction::Allow,
        );

        policy.add_rule(rule);

        let decision = policy.evaluate(&session).expect("Failed to evaluate policy");
        assert!(decision.is_allowed());
        assert_eq!(decision.action, AccessAction::Allow);
    }

    #[test]
    fn test_access_control() {
        let access_control = AccessControl::new();
        let session = create_test_session();

        let mut policy = AccessPolicy::new(
            "policy-1".to_string(),
            "Test Policy".to_string(),
            AccessAction::Deny,
        );

        let rule = AccessRule::new(
            "rule-1".to_string(),
            "Allow Rule".to_string(),
            1,
            AccessCondition::TrustLevelRequired(TrustLevel::Low),
            AccessAction::Allow,
        );

        policy.add_rule(rule);

        access_control.create_policy(policy).expect("Failed to create policy");

        let decision = access_control
            .evaluate_access(&session, "policy-1")
            .expect("Failed to evaluate access");
        assert!(decision.is_allowed());

        access_control.delete_policy("policy-1").expect("Failed to delete policy");
    }

    #[test]
    fn test_access_decision() {
        let allowed_decision = AccessDecision {
            allowed: true,
            action: AccessAction::Allow,
            reason: "Rule matched".to_string(),
            timestamp: DateTime::<Utc>::now(),
        };

        assert!(allowed_decision.is_allowed());
        assert!(!allowed_decision.requires_action());

        let mfa_decision = AccessDecision {
            allowed: true,
            action: AccessAction::RequireMFA,
            reason: "MFA required".to_string(),
            timestamp: DateTime::<Utc>::now(),
        };

        assert!(mfa_decision.requires_action());
    }

    #[test]
    fn test_policy_rule_management() {
        let access_control = AccessControl::new();

        let policy = AccessPolicy::new(
            "policy-1".to_string(),
            "Test Policy".to_string(),
            AccessAction::Deny,
        );

        access_control.create_policy(policy).expect("Failed to create policy");

        let rule = AccessRule::new(
            "rule-1".to_string(),
            "Allow Rule".to_string(),
            1,
            AccessCondition::TrustLevelRequired(TrustLevel::Low),
            AccessAction::Allow,
        );

        access_control.add_rule("policy-1", rule).expect("Failed to add rule");

        let retrieved_policy = access_control.get_policy("policy-1").expect("Failed to get policy");
        assert_eq!(retrieved_policy.rules.len(), 1);

        access_control.remove_rule("policy-1", "rule-1").expect("Failed to remove rule");

        let updated_policy = access_control.get_policy("policy-1").expect("Failed to get policy");
        assert_eq!(updated_policy.rules.len(), 0);
    }
}
