#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-trust session management.
//!
//! This module provides session creation, storage, verification, extension, and
//! revocation for zero-trust authentication flows.

use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::unified_api::error::CryptoError;

use super::primitives::{SecurityContext, TrustLevel};

const SESSION_ID_LENGTH: usize = 32;
const _DEFAULT_SESSION_TIMEOUT_SECS: u64 = 3600;
const MAX_SESSIONS_PER_USER: usize = 10;

#[derive(Debug, Clone)]
pub struct ZeroTrustSession {
    pub session_id: String,
    pub user_id: String,
    pub did: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_verified: DateTime<Utc>,
    pub next_verification: DateTime<Utc>,
    pub verification_count: u32,
    pub trust_level: TrustLevel,
    pub security_context: SecurityContext,
    pub metadata: HashMap<String, String>,
}

impl ZeroTrustSession {
    /// Create a new Zero Trust session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID or user ID is empty, or if the
    /// duration parameters would cause overflow.
    pub fn new(
        session_id: String,
        user_id: String,
        did: Option<String>,
        trust_level: TrustLevel,
        duration: Duration,
        verification_interval: Duration,
        security_context: SecurityContext,
    ) -> Result<Self, CryptoError> {
        if session_id.is_empty() {
            tracing::error!(
                target: "zero_trust::session",
                "Session creation failed: Session ID cannot be empty"
            );
            return Err(CryptoError::InvalidInput("Session ID cannot be empty".to_string()));
        }

        if user_id.is_empty() {
            tracing::error!(
                target: "zero_trust::session",
                "Session creation failed: User ID cannot be empty"
            );
            return Err(CryptoError::InvalidInput("User ID cannot be empty".to_string()));
        }

        let now = Utc::now();

        let expires_at = now
            .checked_add(duration)
            .ok_or_else(|| CryptoError::InvalidInput("Invalid expiration time".to_string()))?;

        let next_verification = now
            .checked_add(verification_interval)
            .ok_or_else(|| CryptoError::InvalidInput("Invalid verification time".to_string()))?;

        tracing::info!(
            target: "zero_trust::session",
            session_id = %session_id,
            trust_level = ?trust_level,
            expires_at = %expires_at,
            "Zero Trust session created"
        );

        Ok(Self {
            session_id,
            user_id,
            did,
            created_at: now,
            expires_at,
            last_verified: now,
            next_verification,
            verification_count: 0,
            trust_level,
            security_context,
            metadata: HashMap::new(),
        })
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at.signed_duration_since(Utc::now()).to_std() {
            Ok(duration) => duration.as_millis() > 0,
            Err(_) => false,
        }
    }

    pub fn needs_verification(&self) -> bool {
        match self.next_verification.signed_duration_since(Utc::now()).to_std() {
            Ok(duration) => duration.as_millis() > 0,
            Err(_) => true,
        }
    }

    pub fn extend(&mut self, additional_time: Duration) -> Result<(), CryptoError> {
        self.expires_at = self.expires_at.checked_add(additional_time).ok_or_else(|| {
            CryptoError::InvalidInput("Cannot extend session: overflow".to_string())
        })?;

        Ok(())
    }

    /// Verify the session and update verification timestamps.
    ///
    /// # Errors
    ///
    /// Returns an error if the session has expired.
    pub fn verify(&mut self) -> Result<(), CryptoError> {
        if self.is_expired() {
            tracing::warn!(
                target: "zero_trust::session",
                session_id = %self.session_id,
                "Session verification failed: session has expired"
            );
            return Err(CryptoError::InvalidInput("Session has expired".to_string()));
        }

        self.last_verified = Utc::now();

        let verification_interval =
            Duration::from_secs(self.trust_level.verification_interval_secs());
        self.next_verification = Utc::now()
            .checked_add(verification_interval)
            .ok_or_else(|| CryptoError::InvalidInput("Invalid verification time".to_string()))?;

        self.verification_count = self.verification_count.saturating_add(1);

        tracing::info!(
            target: "zero_trust::session",
            session_id = %self.session_id,
            verification_count = self.verification_count,
            "Zero Trust session verified successfully"
        );

        Ok(())
    }

    /// Downgrade the trust level of this session.
    ///
    /// Only downgrades if the new level is lower than the current level.
    pub fn downgrade_trust(&mut self, new_level: TrustLevel) {
        if new_level < self.trust_level {
            let old_level = self.trust_level;
            self.trust_level = new_level;
            self.next_verification = Utc::now()
                .checked_add(Duration::from_secs(new_level.verification_interval_secs()))
                .unwrap_or(self.next_verification);

            tracing::info!(
                target: "zero_trust::trust",
                session_id = %self.session_id,
                from_level = ?old_level,
                to_level = ?new_level,
                "Zero Trust trust level downgraded"
            );
        }
    }

    /// Upgrade the trust level of this session.
    ///
    /// Only upgrades if the new level is higher than the current level.
    pub fn upgrade_trust(&mut self, new_level: TrustLevel) {
        if new_level > self.trust_level {
            let old_level = self.trust_level;
            self.trust_level = new_level;
            self.next_verification = Utc::now()
                .checked_add(Duration::from_secs(new_level.verification_interval_secs()))
                .unwrap_or(self.next_verification);

            tracing::info!(
                target: "zero_trust::trust",
                session_id = %self.session_id,
                from_level = ?old_level,
                to_level = ?new_level,
                "Zero Trust trust level upgraded"
            );
        }
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    pub fn age(&self) -> Result<Duration, CryptoError> {
        self.created_at
            .timestamp() as u64
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid timestamp: {}", e)))
    }

    pub fn time_until_expiration(&self) -> Result<Duration, CryptoError> {
        self.expires_at
            .signed_duration_since(Utc::now()).to_std()
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid expiration time: {}", e)))
    }
}

struct SessionStoreInternalState {
    sessions: HashMap<String, ZeroTrustSession>,
    user_sessions: HashMap<String, Vec<String>>,
}

pub struct SessionStore {
    pub(crate) internal_state: Arc<RwLock<SessionStoreInternalState>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            internal_state: Arc::new(RwLock::new(SessionStoreInternalState {
                sessions: HashMap::new(),
                user_sessions: HashMap::new(),
            })),
        }
    }

    pub fn create_session(
        &self,
        user_id: &str,
        did: Option<&str>,
        trust_level: TrustLevel,
        duration_secs: u64,
        security_context: SecurityContext,
    ) -> Result<ZeroTrustSession, CryptoError> {
        if user_id.is_empty() {
            return Err(CryptoError::InvalidInput("User ID cannot be empty".to_string()));
        }

        self.cleanup_user_sessions(user_id)?;

        let session_id = generate_session_id()?;
        let duration = Duration::from_secs(duration_secs);
        let verification_interval = Duration::from_secs(trust_level.verification_interval_secs());

        let session = ZeroTrustSession::new(
            session_id.clone(),
            user_id.to_string(),
            did.map(|s| s.to_string()),
            trust_level,
            duration,
            verification_interval,
            security_context,
        )?;

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            sessions.insert(session_id.clone(), session.clone());
        }

        {
            let mut user_sessions = self
                .user_sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            user_sessions
                .entry(user_id.to_string())
                .or_insert_with(Vec::new)
                .push(session_id.clone());
        }

        Ok(session)
    }

    pub fn get_session(&self, session_id: &str) -> Result<ZeroTrustSession, CryptoError> {
        if session_id.is_empty() {
            return Err(CryptoError::InvalidInput("Session ID cannot be empty".to_string()));
        }

        let sessions = self
            .sessions
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match sessions.get(session_id) {
            Some(session) if !session.is_expired() => Ok(session.clone()),
            Some(_) => Err(CryptoError::InvalidInput("Session has expired".to_string())),
            None => Err(CryptoError::InvalidInput("Session not found".to_string())),
        }
    }

    pub fn list_sessions(&self, user_id: &str) -> Result<Vec<ZeroTrustSession>, CryptoError> {
        if user_id.is_empty() {
            return Err(CryptoError::InvalidInput("User ID cannot be empty".to_string()));
        }

        let user_sessions = self
            .internal_state
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?.user_sessions;

        match user_sessions.get(user_id) {
            Some(session_ids) => {
                let sessions = self
.internal_state
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?.sessions;

                let mut result = Vec::new();
                for session_id in session_ids {
                    if let Some(session) = sessions.get(session_id)
                        && !session.is_expired()
                    {
                        result.push(session.clone());
                    }
                }

                Ok(result)
            }
            None => Ok(Vec::new()),
        }
    }

    pub fn verify_session(&self, session_id: &str) -> Result<bool, CryptoError> {
        let mut session = self.get_session(session_id)?;

        if !session.is_expired() && !session.needs_verification() {
            Ok(true)
        } else if !session.is_expired() && session.needs_verification() {
            session.verify()?;

            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            sessions.insert(session_id.to_string(), session);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn extend_session(
        &self,
        session_id: &str,
        additional_secs: u64,
    ) -> Result<(), CryptoError> {
        let mut session = self.get_session(session_id)?;

        session.extend(Duration::from_secs(additional_secs))?;

        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        sessions.insert(session_id.to_string(), session);
        Ok(())
    }

    /// Revoke a session by session ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is empty or if the session is not found.
    pub fn revoke_session(&self, session_id: &str) -> Result<(), CryptoError> {
        if session_id.is_empty() {
            tracing::error!(
                target: "zero_trust::session",
                "Session revocation failed: Session ID cannot be empty"
            );
            return Err(CryptoError::InvalidInput("Session ID cannot be empty".to_string()));
        }

        let user_id = {
            let sessions = self
                .sessions
                .read()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            match sessions.get(session_id) {
                Some(session) => session.user_id.clone(),
                None => {
                    tracing::warn!(
                        target: "zero_trust::session",
                        session_id = %session_id,
                        "Session revocation failed: session not found"
                    );
                    return Err(CryptoError::InvalidInput("Session not found".to_string()));
                }
            }
        };

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            sessions.remove(session_id);
        }

        {
            let mut user_sessions = self
                .user_sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            if let Some(session_ids) = user_sessions.get_mut(&user_id) {
                session_ids.retain(|id| id != session_id);
            }
        }

        tracing::info!(
            target: "zero_trust::session",
            session_id = %session_id,
            "Zero Trust session revoked"
        );

        Ok(())
    }

    pub fn revoke_user_sessions(&self, user_id: &str) -> Result<usize, CryptoError> {
        if user_id.is_empty() {
            return Err(CryptoError::InvalidInput("User ID cannot be empty".to_string()));
        }

        let session_ids = {
            let mut user_sessions = self
                .user_sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            user_sessions.remove(user_id).unwrap_or_default()
        };

        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        for session_id in &session_ids {
            sessions.remove(session_id);
        }

        Ok(session_ids.len())
    }

    pub fn cleanup_expired_sessions(&self) -> Result<usize, CryptoError> {
        let mut expired_session_ids = Vec::new();

        {
            let sessions = self
                .sessions
                .read()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            for (session_id, session) in sessions.iter() {
                if session.is_expired() {
                    expired_session_ids.push(session_id.clone());
                    if let Ok(mut internal_state) = self.internal_state.write()
                        && let Some(session_ids) = internal_state.user_sessions.get_mut(&session.user_id)
                    {
                        session_ids.retain(|id| id != session_id);
                    }
                }
            }
        }

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

            for session_id in &expired_session_ids {
                sessions.remove(session_id);
            }
        }

        Ok(expired_session_ids.len())
    }

    pub fn session_count(&self) -> Result<usize, CryptoError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;
        Ok(sessions.len())
    }

    pub fn user_session_count(&self, user_id: &str) -> Result<usize, CryptoError> {
        let user_sessions = self
            .user_sessions
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        Ok(user_sessions.get(user_id).map(|ids| ids.len()).unwrap_or(0))
    }

    fn cleanup_user_sessions(&self, user_id: &str) -> Result<(), CryptoError> {
        let mut user_sessions = self
            .user_sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        let session_ids = user_sessions.entry(user_id.to_string()).or_insert_with(Vec::new);

        if session_ids.len() >= MAX_SESSIONS_PER_USER {
            let mut sessions_to_remove = Vec::new();

            for session_id in session_ids.iter() {
                if let Ok(session) = self.get_session(session_id)
                    && session.is_expired()
                {
                    sessions_to_remove.push(session_id.clone());
                }
            }

            if sessions_to_remove.len() + session_ids.len() > MAX_SESSIONS_PER_USER {
                sessions_to_remove
                    .sort_by_key(|id| self.get_session(id).map(|s| s.created_at).ok());

                let remove_count =
                    session_ids.len() + sessions_to_remove.len() - MAX_SESSIONS_PER_USER;
                for session_id in sessions_to_remove.drain(..remove_count) {
                    session_ids.retain(|id| id != &session_id);
                    let mut sessions = self.internal_state.write().map_err(|e| {
                        CryptoError::ConfigurationError(format!("Lock error: {}", e))
                    })?.sessions;
                    sessions.remove(&session_id);
                }
            }
        }

        Ok(())
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn generate_session_id() -> Result<String, CryptoError> {
    let mut id_bytes = vec![0u8; SESSION_ID_LENGTH];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut id_bytes);
    Ok(hex::encode(&id_bytes))
}

pub fn create_session(
    user_id: &str,
    did: Option<&str>,
    trust_level: TrustLevel,
    duration_secs: u64,
) -> Result<ZeroTrustSession, CryptoError> {
    let store = SessionStore::new();
    store.create_session(user_id, did, trust_level, duration_secs, SecurityContext::default())
}

pub fn verify_session(session_id: &str) -> Result<bool, CryptoError> {
    let store = SessionStore::new();
    store.verify_session(session_id)
}

pub fn extend_session(session_id: &str, additional_secs: u64) -> Result<(), CryptoError> {
    let store = SessionStore::new();
    store.extend_session(session_id, additional_secs)
}

pub fn revoke_session(session_id: &str) -> Result<(), CryptoError> {
    let store = SessionStore::new();
    store.revoke_session(session_id)
}

pub fn get_session(session_id: &str) -> Result<ZeroTrustSession, CryptoError> {
    let store = SessionStore::new();
    store.get_session(session_id)
}

pub fn list_sessions(user_id: &str) -> Result<Vec<ZeroTrustSession>, CryptoError> {
    let store = SessionStore::new();
    store.list_sessions(user_id)
}

pub fn cleanup_expired_sessions() -> Result<usize, CryptoError> {
    let store = SessionStore::new();
    store.cleanup_expired_sessions()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_id() {
        let session_id = generate_session_id().expect("Failed to generate session ID");
        assert_eq!(session_id.len(), SESSION_ID_LENGTH * 2);
    }

    #[test]
    fn test_session_creation() {
        let session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_secs(3600),
            Duration::from_secs(0),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        assert_eq!(session.session_id, "session-1");
        assert_eq!(session.user_id, "user-1");
        assert!(!session.is_expired());
        assert!(!session.needs_verification());
    }

    #[test]
    fn test_session_expiration() {
        let session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_millis(10),
            Duration::from_secs(600),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        std::thread::sleep(Duration::from_millis(50));
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_verification() {
        let mut session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_secs(3600),
            Duration::from_millis(10),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        std::thread::sleep(Duration::from_millis(50));

        session.verify().expect("Failed to verify session");
        assert_eq!(session.verification_count, 1);
    }

    #[test]
    fn test_session_extend() {
        let mut session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_millis(10),
            Duration::from_secs(600),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        session.extend(Duration::from_secs(3600)).expect("Failed to extend session");

        std::thread::sleep(Duration::from_millis(50));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_trust_level_upgrade_downgrade() {
        let mut session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_secs(3600),
            Duration::from_secs(600),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        session.upgrade_trust(TrustLevel::High);
        assert_eq!(session.trust_level, TrustLevel::High);

        session.downgrade_trust(TrustLevel::Low);
        assert_eq!(session.trust_level, TrustLevel::Low);
    }

    #[test]
    fn test_session_store() {
        let store = SessionStore::new();

        let session = store
            .create_session("user-1", None, TrustLevel::Medium, 3600, SecurityContext::default())
            .expect("Failed to create session");

        let retrieved = store.get_session(&session.session_id).expect("Failed to get session");
        assert_eq!(retrieved.session_id, session.session_id);

        let user_sessions = store.list_sessions("user-1").expect("Failed to list sessions");
        assert_eq!(user_sessions.len(), 1);

        store.revoke_session(&session.session_id).expect("Failed to revoke session");

        let count = store.session_count().expect("Failed to get session count");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_session_cleanup() {
        let store = SessionStore::new();

        store
            .create_session("user-1", None, TrustLevel::Medium, 0, SecurityContext::default())
            .expect("Failed to create session");

        std::thread::sleep(Duration::from_millis(100));

        let cleaned = store.cleanup_expired_sessions().expect("Failed to cleanup sessions");
        assert_eq!(cleaned, 1);
    }

    #[test]
    fn test_revoke_user_sessions() {
        let store = SessionStore::new();

        store
            .create_session("user-1", None, TrustLevel::Medium, 3600, SecurityContext::default())
            .expect("Failed to create session 1");

        store
            .create_session("user-1", None, TrustLevel::Medium, 3600, SecurityContext::default())
            .expect("Failed to create session 2");

        let count = store.revoke_user_sessions("user-1").expect("Failed to revoke user sessions");
        assert_eq!(count, 2);

        let sessions = store.list_sessions("user-1").expect("Failed to list sessions");
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn test_session_metadata() {
        let mut session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_secs(3600),
            Duration::from_secs(600),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        session.add_metadata("key1".to_string(), "value1".to_string());
        assert_eq!(session.get_metadata("key1"), Some(&"value1".to_string()));
    }
}
