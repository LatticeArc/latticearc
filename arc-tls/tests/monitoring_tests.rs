#![deny(unsafe_code)]
// Test files use unwrap() and panic for assertions
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
// Feature-gated test configurations
#![allow(unexpected_cfgs)]

//! Monitoring module integration tests

#[cfg(feature = "monitoring")]
#[test]
fn test_monitoring_basic_functionality() {
    use arc_tls::monitoring::*;

    let collector = MetricsCollector::default();

    // Test recording operations
    let mut labels = HashMap::new();
    labels.insert("test".to_string(), "value".to_string());

    collector.record_operation(TlsOperation::HandshakeInit, labels.clone());
    collector.record_operation(TlsOperation::HandshakeComplete, labels.clone());

    // Test recording metrics
    collector.record_handshake_duration(Duration::from_millis(100), labels);
    collector.record_bytes(1024, 2048);
    collector.record_cipher_suite("TLS_AES_256_GCM_SHA384");
    collector.record_tls_version("TLSv1.3");

    // Verify metrics
    let tls_metrics = collector.get_tls_metrics();
    assert_eq!(tls_metrics.handshake_attempts, 1);
    assert_eq!(tls_metrics.handshake_successes, 1);
    assert_eq!(tls_metrics.bytes_sent, 1024);
    assert_eq!(tls_metrics.bytes_received, 2048);
}

#[cfg(feature = "monitoring")]
#[test]
fn test_performance_monitoring() {
    use arc_tls::monitoring::*;

    let monitor = PerformanceMonitor::new(10);

    // Test recording latencies
    monitor.record_handshake_latency(Duration::from_millis(50));
    monitor.record_key_exchange_latency(Duration::from_millis(20));
    monitor.record_encryption_latency(Duration::from_millis(5));

    // Test setting gauges
    monitor.set_active_connections(10);
    monitor.set_throughput(1024 * 1024);
    monitor.set_cpu_usage(35.0);
    monitor.set_memory_usage(512.0);

    // Get stats
    let stats = monitor.get_stats();
    assert_eq!(stats.handshake_latency.count, 1);
    assert_eq!(stats.active_connections.value, 10.0);
    assert_eq!(stats.throughput.value, 1024 * 1024.0);
}

#[cfg(feature = "monitoring")]
#[test]
fn test_alert_management() {
    use arc_tls::monitoring::*;

    let alert_manager = AlertManager::new(100);

    // Test adding rules
    let rule = AlertRule::new(
        "test_rule",
        "test_metric",
        AlertCondition::GreaterThan,
        10.0,
        AlertSeverity::High,
    );

    alert_manager.add_rule(rule);
    assert_eq!(alert_manager.get_rules().len(), 1);

    // Test evaluating rules
    let mut metrics = HashMap::new();
    metrics.insert("test_metric".to_string(), 15.0);

    let triggered = alert_manager.evaluate_rules(&metrics);
    assert_eq!(triggered.len(), 1);
}

#[cfg(feature = "monitoring")]
#[test]
fn test_prometheus_exporter() {
    use arc_tls::monitoring::*;

    let exporter = PrometheusExporter::default();

    // Test recording TLS metrics
    let tls_metrics = crate::monitoring::TlsMetrics {
        handshake_attempts: 100,
        handshake_successes: 95,
        handshake_failures: 5,
        avg_handshake_duration: 100.0,
        active_connections: 10,
        bytes_sent: 1024,
        bytes_received: 2048,
        ..Default::default()
    };

    exporter.record_tls_metrics(&tls_metrics);

    // Test rendering metrics
    let rendered = exporter.render_metrics();
    assert!(rendered.contains("tls_handshake_attempts_total"));
    assert!(rendered.contains("tls_handshake_successes_total"));
    assert!(rendered.contains("tls_active_connections"));
}

#[cfg(feature = "monitoring")]
#[test]
fn test_elk_integration() {
    use arc_tls::monitoring::*;

    let elk = ElkIntegration::default();

    // Test logging metrics
    let metric = crate::monitoring::Metric::new("test_metric", MetricType::Counter, 1.0);
    elk.log_metric(&metric);

    // Test logging TLS metrics
    let tls_metrics = crate::monitoring::TlsMetrics::default();
    elk.log_tls_metrics(&tls_metrics);

    // Test logging security events
    let event = SecurityEvent::new(
        SecurityEventType::UnusualLatency,
        AlertSeverity::High,
        "High latency detected",
    );
    elk.log_security_event(&event);

    // Verify buffer
    assert_eq!(elk.buffer_len(), 3);
}
