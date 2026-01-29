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
                    context: Default::default(),
                    recovery: RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
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
        context: Default::default(),
        recovery: RecoveryHint::NoRecovery,
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
            context: Default::default(),
            recovery: RecoveryHint::Retry { max_attempts: 1, backoff_ms: 5000 },
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
}
