#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SP 800-57 Key Lifecycle Management
//!
//! This module implements formal key lifecycle management per NIST SP 800-57
//! requirements, including state transitions, custodianship, and audit trails.
//!
//! # Key States (SP 800-57 Section 3)
//!
//! - **Generation**: Key material is being generated
//! - **Active**: Key is ready for use
//! - **Rotating**: Key rotation in progress (overlap period)
//! - **Retired**: Key scheduled for retirement
//! - **Destroyed**: Key material zeroized
//!
//! # Example
//!
//! ```
//! use arc_core::key_lifecycle::{KeyLifecycleRecord, KeyLifecycleState};
//!
//! let mut record = KeyLifecycleRecord::new(
//!     "key-123".to_string(),
//!     "ML-KEM-768".to_string(),
//!     3,   // security level
//!     365, // rotation interval (days)
//!     30,  // overlap period (days)
//! );
//!
//! // Activate the key
//! record.transition(
//!     KeyLifecycleState::Active,
//!     "alice".to_string(),
//!     "Key generation complete".to_string(),
//!     Some("approval-123".to_string()),
//! ).expect("Valid transition");
//!
//! assert!(record.is_valid_for_use());
//! ```

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// SP 800-57 Section 3: Key Lifecycle States
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyLifecycleState {
    /// Key material generation
    Generation,
    /// Key activation - ready for use
    Active,
    /// Key rotation in progress (overlap period)
    Rotating,
    /// Key scheduled for retirement
    Retired,
    /// Key destruction - material zeroized
    Destroyed,
}

/// SP 800-57 Key State Transitions (formally verifiable)
pub struct KeyStateMachine;

impl KeyStateMachine {
    /// Verify state transition is valid per SP 800-57
    ///
    /// Valid transitions:
    /// - None -> Generation (initial state)
    /// - Generation -> Active (initialization complete)
    /// - Active -> Rotating (rotation initiated)
    /// - Active -> Retired (direct retirement)
    /// - Rotating -> Retired (rotation complete)
    /// - Retired -> Destroyed (cleanup)
    #[must_use]
    pub fn is_valid_transition(from: Option<KeyLifecycleState>, to: KeyLifecycleState) -> bool {
        match (from, to) {
            // Generation is always valid initial state
            (None, KeyLifecycleState::Generation) => true,

            // Generation -> Active (initialization complete)
            (Some(KeyLifecycleState::Generation), KeyLifecycleState::Active) => true,

            // Active -> Rotating (rotation initiated)
            (Some(KeyLifecycleState::Active), KeyLifecycleState::Rotating) => true,

            // Rotating -> Retired (rotation complete)
            (Some(KeyLifecycleState::Rotating), KeyLifecycleState::Retired) => true,

            // Active -> Retired (direct retirement)
            (Some(KeyLifecycleState::Active), KeyLifecycleState::Retired) => true,

            // Retired -> Destroyed (cleanup)
            (Some(KeyLifecycleState::Retired), KeyLifecycleState::Destroyed) => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    /// Get allowed next states from current state
    #[must_use]
    pub fn allowed_next_states(current: KeyLifecycleState) -> Vec<KeyLifecycleState> {
        match current {
            KeyLifecycleState::Generation => vec![KeyLifecycleState::Active],
            KeyLifecycleState::Active => {
                vec![KeyLifecycleState::Rotating, KeyLifecycleState::Retired]
            }
            KeyLifecycleState::Rotating => vec![KeyLifecycleState::Retired],
            KeyLifecycleState::Retired => vec![KeyLifecycleState::Destroyed],
            KeyLifecycleState::Destroyed => vec![],
        }
    }
}

/// SP 800-57 Custodianship (Section 5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCustodian {
    /// Unique identifier for the custodian
    pub custodian_id: String,
    /// Human-readable name
    pub name: String,
    /// Role in key management
    pub role: CustodianRole,
    /// List of responsibilities
    pub responsibilities: Vec<String>,
    /// Approval expiration date
    pub approved_until: chrono::DateTime<chrono::Utc>,
}

/// Roles for key custodians
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodianRole {
    /// Authorized to generate keys
    KeyGenerator,
    /// Authorized to approve key operations
    KeyApprover,
    /// Authorized to destroy keys
    KeyDestroyer,
    /// Authorized to audit key operations
    KeyAuditor,
}

/// Key lifecycle record with audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycleRecord {
    /// Unique key identifier
    pub key_id: String,
    /// Algorithm/key type (e.g., "ML-KEM-768", "ML-DSA-65")
    pub key_type: String,
    /// Security level (1-5)
    pub security_level: u32,

    // State management
    /// Current lifecycle state
    pub current_state: KeyLifecycleState,
    /// History of state transitions
    pub state_history: Vec<StateTransition>,

    // Custodianship
    /// ID of the key generator
    pub generator: Option<String>,
    /// IDs of approvers
    pub approvers: Vec<String>,
    /// ID of the destroyer
    pub destroyer: Option<String>,

    // Timing
    /// When the key was generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// When the key was activated
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When key rotation was initiated
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the key was retired
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the key was destroyed
    pub destroyed_at: Option<chrono::DateTime<chrono::Utc>>,

    // SP 800-57 requirements
    /// How often the key should be rotated (days)
    pub rotation_interval_days: u32,
    /// Overlap period during rotation (days)
    pub overlap_period_days: u32,
}

/// Record of a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Previous state (None if initial)
    pub from_state: Option<KeyLifecycleState>,
    /// New state
    pub to_state: KeyLifecycleState,
    /// When the transition occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// ID of the custodian who performed the transition
    pub custodian_id: String,
    /// Reason for the transition
    pub justification: String,
    /// Approval reference (if applicable)
    pub approval_id: Option<String>,
}

impl KeyLifecycleRecord {
    /// Create new key lifecycle record
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `key_type` - Algorithm/key type (e.g., "ML-KEM-768")
    /// * `security_level` - Security level (1-5)
    /// * `rotation_interval_days` - How often to rotate the key
    /// * `overlap_period_days` - Overlap period during rotation
    #[must_use]
    pub fn new(
        key_id: String,
        key_type: String,
        security_level: u32,
        rotation_interval_days: u32,
        overlap_period_days: u32,
    ) -> Self {
        Self {
            key_id,
            key_type,
            security_level,
            current_state: KeyLifecycleState::Generation,
            state_history: Vec::new(),
            generator: None,
            approvers: Vec::new(),
            destroyer: None,
            generated_at: chrono::Utc::now(),
            activated_at: None,
            rotated_at: None,
            retired_at: None,
            destroyed_at: None,
            rotation_interval_days,
            overlap_period_days,
        }
    }

    /// Transition key to new state with custodianship tracking
    ///
    /// # Arguments
    ///
    /// * `to_state` - Target state
    /// * `custodian_id` - ID of the custodian performing the transition
    /// * `justification` - Reason for the transition
    /// * `approval_id` - Optional approval reference
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidStateTransition` if the transition is invalid
    pub fn transition(
        &mut self,
        to_state: KeyLifecycleState,
        custodian_id: String,
        justification: String,
        approval_id: Option<String>,
    ) -> Result<()> {
        if !KeyStateMachine::is_valid_transition(Some(self.current_state), to_state) {
            return Err(CoreError::InvalidStateTransition {
                from: self.current_state,
                to: to_state,
            });
        }
        let transition = StateTransition {
            from_state: Some(self.current_state),
            to_state,
            timestamp: chrono::Utc::now(),
            custodian_id: custodian_id.clone(),
            justification,
            approval_id,
        };

        self.state_history.push(transition);
        self.current_state = to_state;

        // Update timestamps
        match to_state {
            KeyLifecycleState::Active => self.activated_at = Some(chrono::Utc::now()),
            KeyLifecycleState::Rotating => self.rotated_at = Some(chrono::Utc::now()),
            KeyLifecycleState::Retired => self.retired_at = Some(chrono::Utc::now()),
            KeyLifecycleState::Destroyed => self.destroyed_at = Some(chrono::Utc::now()),
            _ => {}
        }

        // Update custodianship
        // Generator is the custodian who completes key generation (moves to Active)
        // Check the last transition we just added to see if it was from Generation
        if let Some(last_transition) = self.state_history.last()
            && last_transition.from_state == Some(KeyLifecycleState::Generation)
            && to_state == KeyLifecycleState::Active
        {
            self.generator = Some(custodian_id.clone());
        }
        if to_state == KeyLifecycleState::Destroyed {
            self.destroyer = Some(custodian_id);
        }

        Ok(())
    }

    /// Check if key is due for rotation per SP 800-57
    #[must_use]
    pub fn requires_rotation(&self) -> bool {
        if let Some(activated_at) = self.activated_at {
            // Use signed_duration_since for safe duration calculation
            let duration = chrono::Utc::now().signed_duration_since(activated_at);
            let age_days_i64 = duration.num_days();
            // Convert safely: negative ages (future activation) treated as 0
            // Ages larger than u32::MAX are capped (would be ~11.7M years)
            let age_days = u32::try_from(age_days_i64).unwrap_or(0);
            age_days >= self.rotation_interval_days
        } else {
            false
        }
    }

    /// Get key age in days since activation
    #[must_use]
    pub fn age_days(&self) -> Option<u32> {
        self.activated_at.map(|activated| {
            // Use signed_duration_since for safe duration calculation
            let duration = chrono::Utc::now().signed_duration_since(activated);
            let days_i64 = duration.num_days();
            // Convert safely: negative ages (future activation) treated as 0
            u32::try_from(days_i64).unwrap_or(0)
        })
    }

    /// Check if key is in valid state for use
    #[must_use]
    pub fn is_valid_for_use(&self) -> bool {
        matches!(self.current_state, KeyLifecycleState::Active | KeyLifecycleState::Rotating)
    }

    /// Get the number of state transitions
    #[must_use]
    pub fn transition_count(&self) -> usize {
        self.state_history.len()
    }

    /// Add an approver to the key
    pub fn add_approver(&mut self, approver_id: String) {
        if !self.approvers.contains(&approver_id) {
            self.approvers.push(approver_id);
        }
    }
}

// Formal verification with Kani (requires kani toolchain)
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn key_state_machine_destroyed_cannot_transition() {
        let to: KeyLifecycleState = kani::any();

        // Property: Destroyed keys cannot transition to any state
        let is_valid = KeyStateMachine::is_valid_transition(Some(KeyLifecycleState::Destroyed), to);
        kani::assert!(!is_valid, "Destroyed keys should not transition");
    }

    #[kani::proof]
    fn key_state_machine_no_backward_to_generation() {
        let from: KeyLifecycleState = kani::any();

        // Property: Cannot go back to Generation from any state
        kani::assume(from != KeyLifecycleState::Generation);
        let is_valid =
            KeyStateMachine::is_valid_transition(Some(from), KeyLifecycleState::Generation);
        kani::assert!(!is_valid, "Cannot transition back to Generation");
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_state_transitions() {
        // Generation -> Active
        assert!(KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Generation),
            KeyLifecycleState::Active
        ));

        // Active -> Rotating
        assert!(KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Active),
            KeyLifecycleState::Rotating
        ));

        // Rotating -> Retired
        assert!(KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Rotating),
            KeyLifecycleState::Retired
        ));

        // Retired -> Destroyed
        assert!(KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Retired),
            KeyLifecycleState::Destroyed
        ));

        // Active -> Retired (direct)
        assert!(KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Active),
            KeyLifecycleState::Retired
        ));
    }

    #[test]
    fn test_invalid_state_transitions() {
        // Cannot go backwards
        assert!(!KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Active),
            KeyLifecycleState::Generation
        ));

        // Cannot skip states
        assert!(!KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Generation),
            KeyLifecycleState::Destroyed
        ));

        // Destroyed cannot transition
        assert!(!KeyStateMachine::is_valid_transition(
            Some(KeyLifecycleState::Destroyed),
            KeyLifecycleState::Active
        ));
    }

    #[test]
    fn test_allowed_next_states() {
        assert_eq!(
            KeyStateMachine::allowed_next_states(KeyLifecycleState::Generation),
            vec![KeyLifecycleState::Active]
        );

        assert_eq!(
            KeyStateMachine::allowed_next_states(KeyLifecycleState::Active),
            vec![KeyLifecycleState::Rotating, KeyLifecycleState::Retired]
        );

        assert_eq!(KeyStateMachine::allowed_next_states(KeyLifecycleState::Destroyed), vec![]);
    }

    #[test]
    fn test_key_lifecycle_record() {
        let mut record = KeyLifecycleRecord::new(
            "test-key-123".to_string(),
            "ML-KEM-768".to_string(),
            3,
            365,
            30,
        );

        assert_eq!(record.current_state, KeyLifecycleState::Generation);
        assert!(!record.is_valid_for_use());

        // Transition to Active
        record
            .transition(
                KeyLifecycleState::Active,
                "alice".to_string(),
                "Key generation complete".to_string(),
                Some("approval-123".to_string()),
            )
            .unwrap();

        assert_eq!(record.current_state, KeyLifecycleState::Active);
        assert!(record.is_valid_for_use());
        assert_eq!(record.generator, Some("alice".to_string()));
        assert!(record.activated_at.is_some());

        // Check rotation requirement (new key shouldn't need rotation)
        assert!(!record.requires_rotation());
    }

    #[test]
    fn test_rotation_requirement() {
        let mut record = KeyLifecycleRecord::new(
            "test-key-123".to_string(),
            "AES-256".to_string(),
            3,
            90, // 90 day rotation
            7,
        );

        // Manually set activation date to 100 days ago
        record.activated_at = Some(chrono::Utc::now() - chrono::Duration::days(100));

        assert!(record.requires_rotation());
        assert_eq!(record.age_days(), Some(100));
    }

    #[test]
    fn test_transition_validation() {
        let mut record = KeyLifecycleRecord::new(
            "test-key-123".to_string(),
            "ML-DSA-65".to_string(),
            3,
            365,
            30,
        );

        // Invalid transition should fail
        let result = record.transition(
            KeyLifecycleState::Destroyed, // Invalid from Generation
            "alice".to_string(),
            "Invalid transition".to_string(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_add_approver() {
        let mut record = KeyLifecycleRecord::new(
            "test-key-123".to_string(),
            "ML-KEM-768".to_string(),
            3,
            365,
            30,
        );

        record.add_approver("alice".to_string());
        record.add_approver("bob".to_string());
        record.add_approver("alice".to_string()); // Duplicate, should not be added

        assert_eq!(record.approvers.len(), 2);
        assert!(record.approvers.contains(&"alice".to_string()));
        assert!(record.approvers.contains(&"bob".to_string()));
    }
}
