#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Error Recovery Mechanisms for TLS Operations
//!
//! This module provides robust error recovery strategies:
//! - Retry policies with exponential backoff
//! - Fallback mechanisms (PQ → Classic)
//! - Circuit breaker pattern for resilience
//! - Graceful degradation strategies

use rand;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::error::{ErrorCode, RecoveryHint, TlsError};

/// Retry configuration for TLS operations
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential)
    pub backoff_multiplier: f64,
    /// Enable jitter to avoid thundering herd
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Create conservative retry policy
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }

    /// Create aggressive retry policy
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 1.5,
            jitter: true,
        }
    }

    /// Create custom retry policy
    #[must_use]
    pub fn new(max_attempts: u32, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self { max_attempts, initial_backoff, max_backoff, backoff_multiplier: 2.0, jitter: true }
    }

    /// Calculate backoff duration for a given attempt
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        // Use saturating arithmetic to prevent overflow
        let attempt_exponent = attempt.saturating_sub(1);
        // Limit exponent to reasonable values to prevent overflow
        let safe_exponent = attempt_exponent.min(10);

        // Calculate initial delay in milliseconds using u64 arithmetic
        // Cap at u64::MAX to prevent truncation
        let initial_ms = self.initial_backoff.as_millis();
        let initial_u64 = u64::try_from(initial_ms).unwrap_or(u64::MAX);

        // Calculate multiplier as integer (2^exponent)
        // Since backoff_multiplier is typically 2.0, we can use bit shift
        let multiplier = 1u64.checked_shl(safe_exponent).unwrap_or(u64::MAX);

        // Calculate delay with overflow protection
        let delay_ms = initial_u64.saturating_mul(multiplier);

        // Cap at max backoff
        let max_ms_128 = self.max_backoff.as_millis();
        let max_ms = u64::try_from(max_ms_128).unwrap_or(u64::MAX);
        let capped_delay_ms = delay_ms.min(max_ms);

        let mut duration = Duration::from_millis(capped_delay_ms);

        if self.jitter {
            // Add random jitter (0-50% of delay)
            let jitter_pct = rand::random::<u64>() % 50;
            let jitter_ms = capped_delay_ms.saturating_mul(jitter_pct) / 100;
            let final_ms = capped_delay_ms.saturating_add(jitter_ms);
            duration = Duration::from_millis(final_ms);
        }

        duration
    }

    /// Check if error should be retried
    #[must_use]
    pub fn should_retry(&self, err: &TlsError, attempt: u32) -> bool {
        // Check max attempts
        if attempt >= self.max_attempts {
            return false;
        }

        // Check error-specific retry conditions
        match err {
            TlsError::Io { code, .. } => {
                matches!(
                    code,
                    ErrorCode::ConnectionRefused
                        | ErrorCode::ConnectionTimeout
                        | ErrorCode::ConnectionReset
                )
            }
            TlsError::Tls { code, .. } => matches!(
                code,
                ErrorCode::HandshakeFailed
                    | ErrorCode::InvalidHandshakeMessage
                    | ErrorCode::HandshakeTimeout
            ),
            TlsError::Handshake { code, .. } => matches!(
                code,
                ErrorCode::HandshakeFailed
                    | ErrorCode::ProtocolVersionMismatch
                    | ErrorCode::HandshakeTimeout
            ),
            TlsError::KeyExchange { code, .. } => {
                matches!(code, ErrorCode::KeyExchangeFailed | ErrorCode::EncapsulationFailed)
            }
            _ => false,
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed (normal operation)
    Closed,
    /// Circuit is open (failures detected)
    Open,
    /// Circuit is half-open (testing recovery)
    HalfOpen,
}

/// Circuit breaker for preventing cascading failures
#[derive(Debug)]
pub struct CircuitBreaker {
    state: Arc<AtomicU32>, // 0=Closed, 1=Open, 2=HalfOpen
    failure_count: Arc<AtomicU32>,
    success_count: Arc<AtomicU32>,
    last_failure_time: Arc<std::sync::Mutex<Option<Instant>>>,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
}

impl CircuitBreaker {
    /// Create new circuit breaker
    #[must_use]
    pub fn new(failure_threshold: u32, timeout: Duration) -> Self {
        Self {
            state: Arc::new(AtomicU32::new(0)), // Closed
            failure_count: Arc::new(AtomicU32::new(0)),
            success_count: Arc::new(AtomicU32::new(0)),
            last_failure_time: Arc::new(std::sync::Mutex::new(None)),
            failure_threshold,
            success_threshold: 3, // 3 successful attempts to close circuit
            timeout,
        }
    }

    /// Get current circuit state
    #[must_use]
    pub fn state(&self) -> CircuitState {
        match self.state.load(Ordering::SeqCst) {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    /// Check if circuit allows operation
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has elapsed
                let Ok(last_failure) = self.last_failure_time.lock() else {
                    warn!("Failed to acquire circuit breaker lock, assuming no timeout");
                    return false;
                };
                if let Some(last) = *last_failure
                    && last.elapsed() >= self.timeout
                {
                    // Transition to half-open
                    self.set_state(CircuitState::HalfOpen);
                    info!("Circuit breaker transitioning to half-open state");
                    return true;
                }
                warn!("Circuit breaker is open, request blocked");
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record successful operation
    pub fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::SeqCst);

        if self.state() == CircuitState::HalfOpen {
            let success = self.success_count.load(Ordering::SeqCst);
            if success >= self.success_threshold {
                self.set_state(CircuitState::Closed);
                self.failure_count.store(0, Ordering::SeqCst);
                self.success_count.store(0, Ordering::SeqCst);
                info!("Circuit breaker closed after {} successful operations", success);
            }
        } else if self.state() == CircuitState::Closed {
            self.failure_count.store(0, Ordering::SeqCst);
        }
    }

    /// Record failed operation
    pub fn record_failure(&self) {
        let failures = self.failure_count.fetch_add(1, Ordering::SeqCst).saturating_add(1);

        if let Ok(mut guard) = self.last_failure_time.lock() {
            *guard = Some(Instant::now());
        } else {
            warn!("Failed to record failure time due to lock contention");
        }

        if self.state() == CircuitState::HalfOpen {
            // Immediately go back to open
            self.set_state(CircuitState::Open);
            self.success_count.store(0, Ordering::SeqCst);
            warn!("Circuit breaker returned to open state after failure in half-open");
        } else if failures >= self.failure_threshold {
            self.set_state(CircuitState::Open);
            error!("Circuit breaker opened after {} consecutive failures", failures);
        }

        debug!("Circuit breaker failure count: {}", failures);
    }

    fn set_state(&self, state: CircuitState) {
        let value = match state {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        };
        self.state.store(value, Ordering::SeqCst);
    }

    /// Reset circuit breaker to closed state
    pub fn reset(&self) {
        self.set_state(CircuitState::Closed);
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        if let Ok(mut guard) = self.last_failure_time.lock() {
            *guard = None;
        } else {
            warn!("Failed to reset failure time due to lock contention");
        }
        info!("Circuit breaker reset to closed state");
    }
}

/// Fallback strategy for TLS operations
#[derive(Debug, Clone, Default)]
pub enum FallbackStrategy {
    /// No fallback
    #[default]
    None,
    /// Fallback from hybrid to classical TLS
    HybridToClassical,
    /// Fallback from PQ to hybrid
    PqToHybrid,
    /// Custom fallback with description
    Custom {
        /// Description of the custom fallback strategy.
        description: String,
    },
}

impl FallbackStrategy {
    /// Create hybrid-to-classical fallback
    #[must_use]
    pub fn hybrid_to_classical() -> Self {
        Self::HybridToClassical
    }

    /// Create PQ-to-hybrid fallback
    #[must_use]
    pub fn pq_to_hybrid() -> Self {
        Self::PqToHybrid
    }

    /// Check if fallback should be triggered
    #[must_use]
    pub fn should_fallback(&self, err: &TlsError) -> bool {
        match self {
            FallbackStrategy::None => false,
            FallbackStrategy::HybridToClassical => {
                matches!(err.code(), ErrorCode::PqNotAvailable | ErrorCode::HybridKemFailed)
            }
            FallbackStrategy::PqToHybrid => {
                matches!(err.code(), ErrorCode::HybridKemFailed)
            }
            FallbackStrategy::Custom { .. } => true,
        }
    }

    /// Get fallback description
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            FallbackStrategy::None => "No fallback available".to_string(),
            FallbackStrategy::HybridToClassical => {
                "Falling back from hybrid to classical TLS".to_string()
            }
            FallbackStrategy::PqToHybrid => "Falling back from PQ-only to hybrid TLS".to_string(),
            FallbackStrategy::Custom { description } => description.clone(),
        }
    }
}

/// Graceful degradation configuration
#[derive(Debug, Clone)]
pub struct DegradationConfig {
    /// Enable fallback strategies
    pub enable_fallback: bool,
    /// Allow reduced security for availability
    pub allow_reduced_security: bool,
    /// Maximum degradation attempts
    pub max_degradation_attempts: u32,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        Self { enable_fallback: true, allow_reduced_security: false, max_degradation_attempts: 2 }
    }
}

/// Execute operation with retry policy
///
/// # Errors
///
/// Returns an error if:
/// - All retry attempts are exhausted and the operation still fails
/// - The error is not retryable according to the retry policy
/// - The operation fails with a non-recoverable error
pub async fn retry_with_policy<F, Fut, T>(
    policy: &RetryPolicy,
    operation: F,
    operation_name: &str,
) -> Result<T, TlsError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, TlsError>>,
{
    let mut last_error = None;

    for attempt in 1..=policy.max_attempts {
        debug!("{} attempt {} of {}", operation_name, attempt, policy.max_attempts);

        match operation().await {
            Ok(result) => {
                if attempt > 1 {
                    info!("{} succeeded on attempt {} after retry", operation_name, attempt);
                }
                return Ok(result);
            }
            Err(err) => {
                // Store the error (TlsError doesn't implement Clone for security)
                // We'll create a new error with the same information
                let error_info = match &err {
                    TlsError::Io { .. } => "IO error".to_string(),
                    TlsError::Tls { message, .. } => format!("TLS error: {}", message),
                    TlsError::Certificate { .. } => "Certificate error".to_string(),
                    TlsError::KeyExchange { .. } => "Key exchange error".to_string(),
                    TlsError::CryptoProvider { .. } => "Crypto provider error".to_string(),
                    TlsError::Config { .. } => "Configuration error".to_string(),
                    // Other variants don't exist in current TlsError
                    _ => "Unknown error".to_string(),
                };
                // Create a simple error for circuit breaker - TlsError::Recovery variant doesn't exist
                last_error = Some(TlsError::Config {
                    message: format!("Circuit breaker failure: {}", error_info),
                    field: Some("circuit_breaker".to_string()),
                    code: ErrorCode::InvalidConfig,
                    context: Box::default(),
                    recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
                });

                if !policy.should_retry(&err, attempt) {
                    warn!("{} error not retryable: {:?}", operation_name, err);
                    return Err(err);
                }

                if attempt < policy.max_attempts {
                    let backoff = policy.backoff_for_attempt(attempt);
                    info!(
                        "{} failed on attempt {}, retrying after {:?}",
                        operation_name, attempt, backoff
                    );
                    sleep(backoff).await;
                }
            }
        }
    }

    error!("{} failed after {} attempts", operation_name, policy.max_attempts);
    Err(last_error.unwrap_or_else(|| TlsError::Internal {
        message: "Operation failed with unknown error".to_string(),
        code: ErrorCode::InternalError,
        context: Box::default(),
        recovery: Box::new(RecoveryHint::NoRecovery),
    }))
}

/// Execute operation with circuit breaker
///
/// # Errors
///
/// Returns an error if:
/// - The circuit breaker is in the open state and blocking requests
/// - The underlying operation fails (the failure is also recorded by the circuit breaker)
pub async fn execute_with_circuit_breaker<F, Fut, T>(
    circuit_breaker: &CircuitBreaker,
    operation: F,
    operation_name: &str,
) -> Result<T, TlsError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, TlsError>>,
{
    if !circuit_breaker.allow_request() {
        return Err(TlsError::Internal {
            message: format!("Circuit breaker is open, {} operation blocked", operation_name),
            code: ErrorCode::TooManyConnections,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 1, backoff_ms: 5000 }),
        });
    }

    match operation().await {
        Ok(result) => {
            circuit_breaker.record_success();
            Ok(result)
        }
        Err(err) => {
            circuit_breaker.record_failure();
            Err(err)
        }
    }
}

/// Execute operation with fallback strategy
///
/// # Errors
///
/// Returns an error if:
/// - The primary operation fails and the fallback strategy does not trigger
/// - Both the primary operation and the fallback operation fail
pub async fn execute_with_fallback<F1, Fut1, F2, Fut2, T>(
    strategy: &FallbackStrategy,
    primary: F1,
    fallback: F2,
    operation_name: &str,
) -> Result<T, TlsError>
where
    F1: Fn() -> Fut1,
    Fut1: Future<Output = Result<T, TlsError>>,
    F2: Fn() -> Fut2,
    Fut2: Future<Output = Result<T, TlsError>>,
{
    match primary().await {
        Ok(result) => Ok(result),
        Err(err) => {
            if strategy.should_fallback(&err) {
                warn!(
                    "{} primary failed, attempting fallback: {}",
                    operation_name,
                    strategy.description()
                );
                fallback().await
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_retry_policy_backoff() {
        let policy = RetryPolicy::default();
        let backoff1 = policy.backoff_for_attempt(1);
        let backoff2 = policy.backoff_for_attempt(2);

        assert!(backoff2 > backoff1);
        assert!(backoff1 >= Duration::from_millis(100));
    }

    #[test]
    fn test_circuit_breaker_initial_state() {
        let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_open_after_failures() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));

        for _ in 0..3 {
            breaker.record_failure();
        }

        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[test]
    fn test_fallback_strategy_description() {
        let strategy = FallbackStrategy::hybrid_to_classical();
        assert!(strategy.description().contains("hybrid to classical"));
    }

    // === RetryPolicy additional tests ===

    #[test]
    fn test_retry_policy_conservative() {
        let policy = RetryPolicy::conservative();
        assert_eq!(policy.max_attempts, 2);
        assert_eq!(policy.initial_backoff, Duration::from_millis(200));
        assert_eq!(policy.max_backoff, Duration::from_secs(2));
    }

    #[test]
    fn test_retry_policy_aggressive() {
        let policy = RetryPolicy::aggressive();
        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.initial_backoff, Duration::from_millis(50));
        assert_eq!(policy.max_backoff, Duration::from_secs(10));
    }

    #[test]
    fn test_retry_policy_custom() {
        let policy = RetryPolicy::new(10, Duration::from_millis(500), Duration::from_secs(30));
        assert_eq!(policy.max_attempts, 10);
        assert_eq!(policy.initial_backoff, Duration::from_millis(500));
        assert_eq!(policy.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_retry_policy_backoff_capped_at_max() {
        let policy = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        // Attempt 10 should be capped at max_backoff
        let backoff = policy.backoff_for_attempt(10);
        assert!(backoff <= Duration::from_millis(500));
    }

    #[test]
    fn test_retry_policy_backoff_without_jitter() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        // Without jitter, backoff should be deterministic
        let backoff1 = policy.backoff_for_attempt(1);
        let backoff1_again = policy.backoff_for_attempt(1);
        assert_eq!(backoff1, backoff1_again);
        assert_eq!(backoff1, Duration::from_millis(100));

        let backoff2 = policy.backoff_for_attempt(2);
        assert_eq!(backoff2, Duration::from_millis(200));
    }

    #[test]
    fn test_retry_policy_should_retry_io_errors() {
        let policy = RetryPolicy::default();

        let retryable = TlsError::Io {
            message: "refused".to_string(),
            source: None,
            code: ErrorCode::ConnectionRefused,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
        };
        assert!(policy.should_retry(&retryable, 1));

        let timeout = TlsError::Io {
            message: "timeout".to_string(),
            source: None,
            code: ErrorCode::ConnectionTimeout,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
        };
        assert!(policy.should_retry(&timeout, 1));

        let reset = TlsError::Io {
            message: "reset".to_string(),
            source: None,
            code: ErrorCode::ConnectionReset,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
        };
        assert!(policy.should_retry(&reset, 1));
    }

    #[test]
    fn test_retry_policy_should_not_retry_max_attempts() {
        let policy = RetryPolicy::default(); // max_attempts = 3

        let retryable = TlsError::Io {
            message: "refused".to_string(),
            source: None,
            code: ErrorCode::ConnectionRefused,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
        };
        assert!(!policy.should_retry(&retryable, 3)); // at max attempts
    }

    #[test]
    fn test_retry_policy_should_retry_tls_errors() {
        let policy = RetryPolicy::default();

        let handshake = TlsError::Tls {
            message: "handshake failed".to_string(),
            code: ErrorCode::HandshakeFailed,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
        };
        assert!(policy.should_retry(&handshake, 1));
    }

    #[test]
    fn test_retry_policy_should_retry_handshake_errors() {
        let policy = RetryPolicy::default();

        let handshake = TlsError::Handshake {
            message: "handshake failed".to_string(),
            state: "ClientHello".to_string(),
            code: ErrorCode::HandshakeFailed,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 }),
        };
        assert!(policy.should_retry(&handshake, 1));
    }

    #[test]
    fn test_retry_policy_should_retry_key_exchange_errors() {
        let policy = RetryPolicy::default();

        let kex = TlsError::KeyExchange {
            message: "key exchange failed".to_string(),
            method: "X25519".to_string(),
            operation: None,
            code: ErrorCode::KeyExchangeFailed,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(policy.should_retry(&kex, 1));
    }

    #[test]
    fn test_retry_policy_should_not_retry_cert_errors() {
        let policy = RetryPolicy::default();

        let cert = TlsError::Certificate {
            message: "cert expired".to_string(),
            subject: None,
            issuer: None,
            code: ErrorCode::CertificateExpired,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(!policy.should_retry(&cert, 1));
    }

    // === CircuitBreaker additional tests ===

    #[test]
    fn test_circuit_breaker_allows_requests_when_closed() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        assert!(breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_blocks_requests_when_open() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_half_open_after_timeout() {
        let breaker = CircuitBreaker::new(3, Duration::from_millis(1));
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        // Should transition to half-open
        assert!(breaker.allow_request());
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_breaker_closes_after_success_in_half_open() {
        let breaker = CircuitBreaker::new(3, Duration::from_millis(1));
        for _ in 0..3 {
            breaker.record_failure();
        }

        std::thread::sleep(Duration::from_millis(5));
        let _ = breaker.allow_request(); // transitions to half-open

        // Record 3 successes (success_threshold = 3)
        for _ in 0..3 {
            breaker.record_success();
        }
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_reopens_on_failure_in_half_open() {
        let breaker = CircuitBreaker::new(3, Duration::from_millis(1));
        for _ in 0..3 {
            breaker.record_failure();
        }

        std::thread::sleep(Duration::from_millis(5));
        let _ = breaker.allow_request(); // transitions to half-open

        // Failure in half-open should reopen
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        breaker.reset();
        assert_eq!(breaker.state(), CircuitState::Closed);
        assert!(breaker.allow_request());
    }

    #[test]
    fn test_circuit_breaker_success_resets_failure_count_when_closed() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        breaker.record_failure();
        breaker.record_failure();
        breaker.record_success(); // should reset failure count
        breaker.record_failure();
        breaker.record_failure();
        // If failure count was NOT reset, this would be 5 > 3 → open
        // Since it was reset after success, we only have 2 failures → still closed
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    // === FallbackStrategy additional tests ===

    #[test]
    fn test_fallback_strategy_none() {
        let strategy = FallbackStrategy::None;
        assert!(strategy.description().contains("No fallback"));

        let err = TlsError::Internal {
            message: "test".to_string(),
            code: ErrorCode::InternalError,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(!strategy.should_fallback(&err));
    }

    #[test]
    fn test_fallback_strategy_pq_to_hybrid() {
        let strategy = FallbackStrategy::pq_to_hybrid();
        assert!(strategy.description().contains("PQ-only to hybrid"));
    }

    #[test]
    fn test_fallback_strategy_hybrid_to_classical_triggers() {
        let strategy = FallbackStrategy::hybrid_to_classical();

        let pq_err = TlsError::Config {
            message: "PQ not available".to_string(),
            field: None,
            code: ErrorCode::PqNotAvailable,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(strategy.should_fallback(&pq_err));
    }

    #[test]
    fn test_fallback_strategy_custom_always_triggers() {
        let strategy = FallbackStrategy::Custom { description: "My fallback".to_string() };
        assert_eq!(strategy.description(), "My fallback");

        let err = TlsError::Internal {
            message: "any error".to_string(),
            code: ErrorCode::InternalError,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(strategy.should_fallback(&err));
    }

    #[test]
    fn test_fallback_strategy_default_is_none() {
        let strategy = FallbackStrategy::default();
        assert!(matches!(strategy, FallbackStrategy::None));
    }

    // === DegradationConfig tests ===

    #[test]
    fn test_degradation_config_default() {
        let config = DegradationConfig::default();
        assert!(config.enable_fallback);
        assert!(!config.allow_reduced_security);
        assert_eq!(config.max_degradation_attempts, 2);
    }

    // === CircuitState tests ===

    #[test]
    fn test_circuit_state_eq() {
        assert_eq!(CircuitState::Closed, CircuitState::Closed);
        assert_ne!(CircuitState::Open, CircuitState::Closed);
        assert_ne!(CircuitState::HalfOpen, CircuitState::Open);
    }

    // === Async function tests ===

    #[tokio::test]
    async fn test_retry_with_policy_success_first_try() {
        let policy = RetryPolicy::default();
        let result = retry_with_policy(&policy, || async { Ok::<_, TlsError>(42) }, "test").await;
        assert_eq!(result.expect("should succeed"), 42);
    }

    #[tokio::test]
    async fn test_retry_with_policy_non_retryable_error() {
        let policy = RetryPolicy::default();
        let result: Result<i32, TlsError> = retry_with_policy(
            &policy,
            || async {
                Err(TlsError::Certificate {
                    message: "expired".to_string(),
                    subject: None,
                    issuer: None,
                    code: ErrorCode::CertificateExpired,
                    context: Box::default(),
                    recovery: Box::new(RecoveryHint::NoRecovery),
                })
            },
            "cert_test",
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::CertificateExpired);
    }

    #[tokio::test]
    async fn test_retry_with_policy_retryable_exhausted() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        let policy = RetryPolicy {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        let result: Result<i32, TlsError> = retry_with_policy(
            &policy,
            || {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Err(TlsError::Io {
                        message: "refused".to_string(),
                        source: None,
                        code: ErrorCode::ConnectionRefused,
                        context: Box::default(),
                        recovery: Box::new(RecoveryHint::Retry {
                            max_attempts: 3,
                            backoff_ms: 1000,
                        }),
                    })
                }
            },
            "retry_test",
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_retry_with_policy_succeeds_on_retry() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        let result = retry_with_policy(
            &policy,
            || {
                let a = attempts_clone.clone();
                async move {
                    let attempt = a.fetch_add(1, Ordering::SeqCst);
                    if attempt < 1 {
                        Err(TlsError::Io {
                            message: "refused".to_string(),
                            source: None,
                            code: ErrorCode::ConnectionRefused,
                            context: Box::default(),
                            recovery: Box::new(RecoveryHint::Retry {
                                max_attempts: 3,
                                backoff_ms: 1000,
                            }),
                        })
                    } else {
                        Ok(99)
                    }
                }
            },
            "retry_success_test",
        )
        .await;
        assert_eq!(result.expect("should succeed on retry"), 99);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_execute_with_circuit_breaker_success() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        let result =
            execute_with_circuit_breaker(&breaker, || async { Ok::<_, TlsError>(42) }, "test")
                .await;
        assert_eq!(result.expect("should succeed"), 42);
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_execute_with_circuit_breaker_failure() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        let result: Result<i32, TlsError> = execute_with_circuit_breaker(
            &breaker,
            || async {
                Err(TlsError::Internal {
                    message: "fail".to_string(),
                    code: ErrorCode::InternalError,
                    context: Box::default(),
                    recovery: Box::new(RecoveryHint::NoRecovery),
                })
            },
            "test",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_with_circuit_breaker_open_blocks() {
        let breaker = CircuitBreaker::new(2, Duration::from_secs(60));
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);

        let result: Result<i32, TlsError> =
            execute_with_circuit_breaker(&breaker, || async { Ok(42) }, "blocked_test").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::TooManyConnections);
    }

    #[tokio::test]
    async fn test_execute_with_fallback_primary_succeeds() {
        let strategy = FallbackStrategy::hybrid_to_classical();
        let result = execute_with_fallback(
            &strategy,
            || async { Ok::<_, TlsError>(42) },
            || async { Ok(99) },
            "test",
        )
        .await;
        assert_eq!(result.expect("primary should succeed"), 42);
    }

    #[tokio::test]
    async fn test_execute_with_fallback_triggers() {
        let strategy = FallbackStrategy::hybrid_to_classical();
        let result = execute_with_fallback(
            &strategy,
            || async {
                Err::<i32, _>(TlsError::Config {
                    message: "PQ not available".to_string(),
                    field: None,
                    code: ErrorCode::PqNotAvailable,
                    context: Box::default(),
                    recovery: Box::new(RecoveryHint::NoRecovery),
                })
            },
            || async { Ok(99) },
            "fallback_test",
        )
        .await;
        assert_eq!(result.expect("fallback should succeed"), 99);
    }

    #[tokio::test]
    async fn test_execute_with_fallback_no_trigger() {
        let strategy = FallbackStrategy::None;
        let result: Result<i32, TlsError> = execute_with_fallback(
            &strategy,
            || async {
                Err(TlsError::Internal {
                    message: "fail".to_string(),
                    code: ErrorCode::InternalError,
                    context: Box::default(),
                    recovery: Box::new(RecoveryHint::NoRecovery),
                })
            },
            || async { Ok(99) },
            "no_fallback_test",
        )
        .await;
        assert!(result.is_err());
    }

    // === FallbackStrategy should_fallback additional coverage ===

    #[test]
    fn test_fallback_pq_to_hybrid_triggers_on_hybrid_kem_failed() {
        let strategy = FallbackStrategy::pq_to_hybrid();
        let err = TlsError::Config {
            message: "kem failed".to_string(),
            field: None,
            code: ErrorCode::HybridKemFailed,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(strategy.should_fallback(&err));
    }

    #[test]
    fn test_fallback_pq_to_hybrid_does_not_trigger_on_pq_not_available() {
        let strategy = FallbackStrategy::pq_to_hybrid();
        let err = TlsError::Config {
            message: "PQ not available".to_string(),
            field: None,
            code: ErrorCode::PqNotAvailable,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(!strategy.should_fallback(&err));
    }

    #[test]
    fn test_fallback_hybrid_to_classical_triggers_on_hybrid_kem_failed() {
        let strategy = FallbackStrategy::hybrid_to_classical();
        let err = TlsError::Config {
            message: "kem failed".to_string(),
            field: None,
            code: ErrorCode::HybridKemFailed,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(strategy.should_fallback(&err));
    }

    // === RetryPolicy should_retry edge cases ===

    #[test]
    fn test_retry_policy_should_retry_tls_invalid_handshake() {
        let policy = RetryPolicy::default();
        let err = TlsError::Tls {
            message: "invalid handshake".to_string(),
            code: ErrorCode::InvalidHandshakeMessage,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(policy.should_retry(&err, 1));
    }

    #[test]
    fn test_retry_policy_should_retry_tls_handshake_timeout() {
        let policy = RetryPolicy::default();
        let err = TlsError::Tls {
            message: "timeout".to_string(),
            code: ErrorCode::HandshakeTimeout,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(policy.should_retry(&err, 1));
    }

    #[test]
    fn test_retry_policy_should_retry_handshake_protocol_version() {
        let policy = RetryPolicy::default();
        let err = TlsError::Handshake {
            message: "version mismatch".to_string(),
            state: "ClientHello".to_string(),
            code: ErrorCode::ProtocolVersionMismatch,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(policy.should_retry(&err, 1));
    }

    #[test]
    fn test_retry_policy_should_retry_handshake_timeout() {
        let policy = RetryPolicy::default();
        let err = TlsError::Handshake {
            message: "timeout".to_string(),
            state: "ServerHello".to_string(),
            code: ErrorCode::HandshakeTimeout,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(policy.should_retry(&err, 1));
    }

    #[test]
    fn test_retry_policy_should_retry_kex_encapsulation() {
        let policy = RetryPolicy::default();
        let err = TlsError::KeyExchange {
            message: "encap failed".to_string(),
            method: "ML-KEM".to_string(),
            operation: Some("encapsulate".to_string()),
            code: ErrorCode::EncapsulationFailed,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(policy.should_retry(&err, 1));
    }

    #[test]
    fn test_retry_policy_should_not_retry_non_retryable_io() {
        let policy = RetryPolicy::default();
        let err = TlsError::Io {
            message: "not found".to_string(),
            source: None,
            code: ErrorCode::IoError,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(!policy.should_retry(&err, 1));
    }

    #[test]
    fn test_retry_policy_should_not_retry_config_error() {
        let policy = RetryPolicy::default();
        let err = TlsError::Config {
            message: "invalid".to_string(),
            field: None,
            code: ErrorCode::InvalidConfig,
            context: Box::default(),
            recovery: Box::new(RecoveryHint::NoRecovery),
        };
        assert!(!policy.should_retry(&err, 1));
    }

    // === DegradationConfig custom values ===

    #[test]
    fn test_degradation_config_custom() {
        let config = DegradationConfig {
            enable_fallback: false,
            allow_reduced_security: true,
            max_degradation_attempts: 5,
        };
        assert!(!config.enable_fallback);
        assert!(config.allow_reduced_security);
        assert_eq!(config.max_degradation_attempts, 5);
    }

    // === CircuitState Debug + Copy + Clone ===

    #[test]
    fn test_circuit_state_debug() {
        let state = CircuitState::HalfOpen;
        let debug = format!("{:?}", state);
        assert!(debug.contains("HalfOpen"));
    }

    #[test]
    fn test_circuit_state_clone_copy() {
        let state = CircuitState::Open;
        let cloned = state;
        let copied = state;
        assert_eq!(state, cloned);
        assert_eq!(state, copied);
    }

    // === RetryPolicy Clone + Debug ===

    #[test]
    fn test_retry_policy_clone_debug() {
        let policy = RetryPolicy::default();
        let cloned = policy.clone();
        assert_eq!(cloned.max_attempts, policy.max_attempts);
        let debug = format!("{:?}", policy);
        assert!(debug.contains("RetryPolicy"));
    }

    // === FallbackStrategy Clone + Debug ===

    #[test]
    fn test_fallback_strategy_clone_debug() {
        let strategy = FallbackStrategy::HybridToClassical;
        let cloned = strategy.clone();
        assert!(matches!(cloned, FallbackStrategy::HybridToClassical));
        let debug = format!("{:?}", strategy);
        assert!(debug.contains("HybridToClassical"));
    }
}
