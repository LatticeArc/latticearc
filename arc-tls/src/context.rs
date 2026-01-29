#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Error Context Propagation
//!
//! This module provides utilities for propagating context through TLS operations:
//! - Operation context tracking
//! - Error chain management
//! - Diagnostic information collection
//! - Distributed trace context propagation

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// TLS operation context
#[derive(Debug, Clone)]
pub struct TlsContext {
    /// Unique operation ID
    pub operation_id: String,
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
    /// Parent span ID for span context
    pub parent_span_id: Option<String>,
    /// Operation name
    pub operation_name: String,
    /// Peer address (client or server)
    pub peer_addr: Option<SocketAddr>,
    /// Domain name (for SNI)
    pub domain: Option<String>,
    /// TLS mode being used
    pub mode: Option<String>,
    /// Key exchange method
    pub kex_method: Option<String>,
    /// Connection start time
    pub start_time: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Default for TlsContext {
    fn default() -> Self {
        Self::new("unknown")
    }
}

impl TlsContext {
    /// Create new TLS context
    #[must_use]
    pub fn new(operation_name: &str) -> Self {
        Self {
            operation_id: Uuid::new_v4().to_string(),
            trace_id: None,
            parent_span_id: None,
            operation_name: operation_name.to_string(),
            peer_addr: None,
            domain: None,
            mode: None,
            kex_method: None,
            start_time: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create context from existing trace ID
    #[must_use]
    pub fn with_trace(operation_name: &str, trace_id: String) -> Self {
        let mut ctx = Self::new(operation_name);
        ctx.trace_id = Some(trace_id);
        ctx
    }

    /// Create child context from parent
    #[must_use]
    pub fn child(&self, operation_name: &str) -> Self {
        let mut child = Self::new(operation_name);
        child.trace_id = self.trace_id.clone();
        child.parent_span_id = Some(self.operation_id.clone());
        child.peer_addr = self.peer_addr;
        child.domain = self.domain.clone();
        child.mode = self.mode.clone();
        child.kex_method = self.kex_method.clone();
        child
    }

    /// Set peer address
    #[must_use]
    pub fn with_peer(mut self, addr: SocketAddr) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    /// Set domain name
    #[must_use]
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.domain = Some(domain.to_string());
        self
    }

    /// Set TLS mode
    #[must_use]
    pub fn with_mode(mut self, mode: &str) -> Self {
        self.mode = Some(mode.to_string());
        self
    }

    /// Set key exchange method
    #[must_use]
    pub fn with_kex_method(mut self, method: &str) -> Self {
        self.kex_method = Some(method.to_string());
        self
    }

    /// Add metadata
    #[must_use]
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Get metadata value
    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Get elapsed time since start
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        Utc::now()
            .signed_duration_since(self.start_time)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO)
    }

    /// Format context as string
    #[must_use]
    pub fn format(&self) -> String {
        let mut parts =
            vec![format!("op={}", self.operation_name), format!("id={}", self.operation_id)];

        if let Some(ref trace_id) = self.trace_id {
            parts.push(format!("trace={}", trace_id));
        }

        if let Some(ref peer) = self.peer_addr {
            parts.push(format!("peer={}", peer));
        }

        if let Some(ref domain) = self.domain {
            parts.push(format!("domain={}", domain));
        }

        if let Some(ref mode) = self.mode {
            parts.push(format!("mode={}", mode));
        }

        parts.join(" ")
    }
}

impl fmt::Display for TlsContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// Error chain for tracking error propagation
#[derive(Debug, Clone)]
pub struct ErrorChain {
    /// Chain of errors
    pub errors: Vec<ErrorLink>,
}

impl Default for ErrorChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorChain {
    /// Create new error chain
    #[must_use]
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Add error to chain
    pub fn push(&mut self, link: ErrorLink) {
        self.errors.push(link);
    }

    /// Add error from TlsError
    pub fn push_tls_error(&mut self, err: &crate::error::TlsError, context: &TlsContext) {
        let link = ErrorLink {
            error_type: "TlsError".to_string(),
            message: err.to_string(),
            code: Some(err.code().to_string()),
            context: context.clone(),
            timestamp: Utc::now(),
        };
        self.push(link);
    }

    /// Check if chain is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get number of errors in chain
    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Format chain as string
    #[must_use]
    pub fn format(&self) -> String {
        if self.is_empty() {
            return "No errors".to_string();
        }

        self.errors
            .iter()
            .enumerate()
            .map(|(i, link)| {
                let ts = link.timestamp.timestamp().unsigned_abs();
                format!(
                    "[{i}][{ts}] {} (code: {:?}) - {}",
                    link.error_type, link.code, link.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl fmt::Display for ErrorChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// Individual error link in chain
#[derive(Debug, Clone)]
pub struct ErrorLink {
    /// Error type name
    pub error_type: String,
    /// Error message
    pub message: String,
    /// Error code (if available)
    pub code: Option<String>,
    /// Context when error occurred
    pub context: TlsContext,
    /// Timestamp of error
    pub timestamp: DateTime<Utc>,
}

impl ErrorLink {
    /// Create new error link
    #[must_use]
    pub fn new(error_type: &str, message: &str, context: &TlsContext) -> Self {
        Self {
            error_type: error_type.to_string(),
            message: message.to_string(),
            code: None,
            context: context.clone(),
            timestamp: Utc::now(),
        }
    }

    /// Create error link with code
    #[must_use]
    pub fn with_code(error_type: &str, message: &str, code: &str, context: &TlsContext) -> Self {
        let mut link = Self::new(error_type, message, context);
        link.code = Some(code.to_string());
        link
    }
}

/// Diagnostic information for errors
#[derive(Debug, Clone)]
pub struct DiagnosticInfo {
    /// Error context
    pub context: TlsContext,
    /// Error chain
    pub chain: ErrorChain,
    /// System information
    pub system_info: SystemInfo,
    /// Recommendations
    pub recommendations: Vec<String>,
}

impl DiagnosticInfo {
    /// Create diagnostic info from context and error
    #[must_use]
    pub fn new(context: &TlsContext, err: &crate::error::TlsError) -> Self {
        let mut chain = ErrorChain::new();
        chain.push_tls_error(err, context);

        let recommendations = generate_recommendations(err);

        Self {
            context: context.clone(),
            chain,
            system_info: SystemInfo::collect(),
            recommendations,
        }
    }

    /// Format diagnostic as string
    #[must_use]
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str("=== TLS Error Diagnostic ===\n\n");
        output.push_str(&format!("Context: {}\n", self.context));
        output.push_str(&format!("Elapsed: {:?}\n", self.context.elapsed()));

        output.push_str("\n--- Error Chain ---\n");
        output.push_str(&self.chain.format());

        output.push_str("\n--- System Info ---\n");
        output.push_str(&self.system_info.format());

        if !self.recommendations.is_empty() {
            output.push_str("\n--- Recommendations ---\n");
            for (i, rec) in self.recommendations.iter().enumerate() {
                let num = i.saturating_add(1);
                output.push_str(&format!("{num}. {rec}\n"));
            }
        }

        output
    }
}

impl fmt::Display for DiagnosticInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// System information for diagnostics
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// Platform
    pub platform: String,
    /// Rust version
    pub rust_version: String,
    /// LatticeArc TLS version
    pub tls_version: String,
    /// Feature flags
    pub features: Vec<String>,
}

impl SystemInfo {
    /// Collect system information
    #[must_use]
    pub fn collect() -> Self {
        // All features are always enabled in the open-core library
        let features = vec!["pq".to_string(), "hybrid".to_string()];

        Self {
            platform: std::env::consts::OS.to_string(),
            rust_version: std::env::var("RUSTC").unwrap_or_else(|_| "unknown".to_string()),
            tls_version: env!("CARGO_PKG_VERSION").to_string(),
            features,
        }
    }

    /// Format as string
    #[must_use]
    pub fn format(&self) -> String {
        format!(
            "Platform: {}\nRust: {}\nLatticeArc-TLS: {}\nFeatures: {}",
            self.platform,
            self.rust_version,
            self.tls_version,
            self.features.join(", ")
        )
    }
}

/// Generate recommendations based on error
fn generate_recommendations(err: &crate::error::TlsError) -> Vec<String> {
    let mut recommendations = Vec::new();

    match err {
        crate::error::TlsError::PqNotAvailable { .. } => {
            recommendations.push("Consider using classical TLS mode".to_string());
            recommendations.push("Ensure 'pq' feature is enabled in Cargo.toml".to_string());
        }
        crate::error::TlsError::Certificate { code, .. } => match code {
            crate::error::ErrorCode::CertificateExpired => {
                recommendations.push("Certificate has expired - renew or replace".to_string());
            }
            crate::error::ErrorCode::CertificateHostnameMismatch => {
                recommendations.push("Check SNI domain matches certificate".to_string());
            }
            crate::error::ErrorCode::CertificateChainIncomplete => {
                recommendations.push("Ensure full certificate chain is configured".to_string());
            }
            _ => {
                recommendations.push("Verify certificate validity and chain".to_string());
            }
        },
        crate::error::TlsError::Io { code, .. } => match code {
            crate::error::ErrorCode::ConnectionRefused => {
                recommendations.push("Check if remote service is running".to_string());
                recommendations.push("Verify firewall rules allow connection".to_string());
            }
            crate::error::ErrorCode::ConnectionTimeout => {
                recommendations.push("Check network connectivity".to_string());
                recommendations.push("Verify remote server is responsive".to_string());
            }
            crate::error::ErrorCode::DnsResolutionFailed => {
                recommendations.push("Check DNS configuration".to_string());
                recommendations.push("Verify domain name is correct".to_string());
            }
            _ => {}
        },
        crate::error::TlsError::Config { .. } => {
            recommendations.push("Review TLS configuration".to_string());
            recommendations.push("Check certificate and key files exist".to_string());
        }
        crate::error::TlsError::Handshake { code, .. } => match code {
            crate::error::ErrorCode::ProtocolVersionMismatch => {
                recommendations.push("Try with different TLS version".to_string());
                recommendations.push("Check if server supports TLS 1.3".to_string());
            }
            crate::error::ErrorCode::CipherSuiteMismatch => {
                recommendations.push("Configure compatible cipher suites".to_string());
            }
            _ => {}
        },
        _ => {
            recommendations.push("Review error details for specific issues".to_string());
        }
    }

    recommendations.push("Check application logs for additional details".to_string());
    recommendations.push("Consider enabling debug logging for more information".to_string());

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_context_default() {
        let ctx = TlsContext::default();
        assert!(!ctx.operation_id.is_empty());
        assert_eq!(ctx.operation_name, "unknown");
    }

    #[test]
    fn test_tls_context_child() {
        let parent = TlsContext::new("parent");
        let child = parent.child("child");

        assert_eq!(child.parent_span_id, Some(parent.operation_id));
        assert_eq!(child.trace_id, parent.trace_id);
    }

    #[test]
    fn test_tls_context_with_metadata() {
        let ctx =
            TlsContext::new("test").with_metadata("key1", "value1").with_metadata("key2", "value2");

        assert_eq!(ctx.get_metadata("key1"), Some(&"value1".to_string()));
        assert_eq!(ctx.get_metadata("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_error_chain_empty() {
        let chain = ErrorChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_error_chain_push() {
        let mut chain = ErrorChain::new();
        let ctx = TlsContext::new("test");
        let link = ErrorLink::new("TestError", "Test message", &ctx);
        chain.push(link);

        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_system_info_collect() {
        let info = SystemInfo::collect();
        assert!(!info.platform.is_empty());
        assert!(!info.rust_version.is_empty());
        assert!(!info.tls_version.is_empty());
    }
}
