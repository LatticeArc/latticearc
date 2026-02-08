# Enterprise-Grade Monitoring and Alerting

This document describes the comprehensive monitoring and alerting system for LatticeArc TLS operations.

## Overview

The monitoring system provides enterprise-grade observability with:

- **Metrics Collection**: Comprehensive TLS operations metrics
- **Performance Monitoring**: Latency histograms, throughput gauges, resource usage
- **Security Event Alerting**: Rule-based alerting with severity levels
- **Prometheus Integration**: Native Prometheus metrics export
- **ELK Stack Integration**: Log aggregation with Elasticsearch, Logstash, Kibana

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Monitoring System                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │ Metrics Collector │──────>│ Performance Monitor│          │
│  └──────────────────┘      └──────────────────┘            │
│           │                         │                        │
│           ▼                         ▼                        │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │   Alert Manager  │──────>│   Exporters      │            │
│  └──────────────────┘      └──────────────────┘            │
│           │                   │        │                      │
│           ▼                   ▼        ▼                      │
│     Security Events      Prometheus    ELK Stack                 │
└─────────────────────────────────────────────────────────────┘
```

## Features

### 1. Metrics Collection

Comprehensive metrics for TLS operations:

- **Handshake Metrics**: Attempts, successes, failures, duration
- **Connection Metrics**: Active connections, bytes sent/received
- **Key Exchange Metrics**: KEX operations, certificate verifications
- **Security Metrics**: TLS versions, cipher suites, ALPN protocols
- **Session Metrics**: Session resumptions, ticket usage

#### Example

```rust
use arc_tls::monitoring::*;

// Initialize monitoring
let collector = init_monitoring()?;

// Record operations
collector.record_operation(TlsOperation::HandshakeInit, labels)?;
collector.record_handshake_duration(Duration::from_millis(100), labels)?;
collector.record_connection_established();

// Record usage
collector.record_bytes(1024, 2048);
collector.record_cipher_suite("TLS_AES_256_GCM_SHA384");
collector.record_tls_version("TLSv1.3");

// Get metrics
let metrics = collector.get_tls_metrics();
println!("Success rate: {:.1}%", metrics.success_rate());
```

### 2. Performance Monitoring

Track performance with histograms and gauges:

- **Latency Tracking**: Handshake, key exchange, encryption, decryption
- **Throughput Monitoring**: Bytes per second, connection rate
- **Resource Monitoring**: CPU usage, memory usage
- **Trend Analysis**: Performance degradation detection
- **Historical Data**: Sliding window of performance data

#### Example

```rust
use arc_tls::monitoring::*;

// Create performance monitor
let monitor = PerformanceMonitor::new(100); // 100 sample history

// Record latencies
monitor.record_handshake_latency(Duration::from_millis(50));
monitor.record_key_exchange_latency(Duration::from_millis(20));
monitor.record_encryption_latency(Duration::from_millis(5));

// Set gauges
monitor.set_active_connections(10);
monitor.set_throughput(1024 * 1024); // 1MB/s
monitor.set_cpu_usage(35.0);
monitor.set_memory_usage(512.0);

// Get stats
let stats = monitor.get_stats();
println!("Avg handshake: {:.2} ms", stats.handshake_latency.avg());

// Check for degradation
if monitor.is_degrading(0.1) {
    warn!("Performance is degrading!");
}
```

### 3. Security Event Alerting

Rule-based alerting for security events:

- **Alert Rules**: Configurable thresholds and conditions
- **Severity Levels**: Info, Low, Medium, High, Critical
- **Security Events**: Failure rate spikes, unusual latency, weak cipher suites
- **Cooldown Periods**: Prevent alert fatigue
- **Event History**: Maintain audit trail

#### Example

```rust
use arc_tls::monitoring::*;

// Create alert manager
let alert_manager = AlertManager::new(1000);

// Add rules
let rule = AlertRule::new(
    "high_handshake_failure_rate",
    "handshake_failure_rate",
    AlertCondition::GreaterThan,
    5.0,
    AlertSeverity::High,
)
.with_cooldown(Duration::from_secs(300));

alert_manager.add_rule(rule);

// Add default rules
for rule in default_alert_rules() {
    alert_manager.add_rule(rule);
}

// Evaluate rules
let metrics = HashMap::from([
    ("handshake_failure_rate".to_string(), 8.5),
    ("handshake_latency_ms".to_string(), 150.0),
]);

let triggered = alert_manager.evaluate_rules(&metrics);
for event in triggered {
    alert_manager.record_event(event);
}

// Get events by severity
let critical_events = alert_manager.get_events_by_severity(AlertSeverity::Critical);
```

### 4. Prometheus Integration

Native Prometheus metrics export:

- **Standard Metrics**: All TLS metrics in Prometheus format
- **Custom Metrics**: Register custom counters, gauges, histograms
- **HTTP Exporter**: Serve metrics at `/metrics` endpoint
- **Metric Labels**: Rich labeling support

#### Example

```rust
use arc_tls::monitoring::*;

// Create Prometheus exporter
let config = ExporterConfig {
    enabled: true,
    listen_address: "0.0.0.0:9090".to_string(),
    metrics_path: "/metrics".to_string(),
};

let exporter = PrometheusExporter::new(config);

// Register custom metrics
let registry = exporter.registry();
let counter = registry.register_counter(
    "tls_custom_operations_total",
    "Total custom operations"
);
counter.inc();

// Record TLS metrics
let tls_metrics = collector.get_tls_metrics();
exporter.record_tls_metrics(&tls_metrics);

// Render metrics
let metrics_output = exporter.render_metrics();
```

### 5. ELK Stack Integration

Log aggregation with ELK stack:

- **Elasticsearch**: Index log entries for search and analysis
- **Logstash**: Structured log pipeline (optional)
- **Kibana**: Dashboard and visualization
- **Log Entries**: JSON-formatted logs with metadata
- **Bulk API**: Efficient batch indexing

#### Example

```rust
use arc_tls::monitoring::*;

// Configure ELK integration
let elk_config = ElkConfig {
    enabled: true,
    elasticsearch_url: "http://localhost:9200".to_string(),
    index_prefix: "latticearc-tls".to_string(),
    kibana_url: Some("http://localhost:5601".to_string()),
    ..Default::default()
};

let elk = ElkIntegration::new(elk_config);

// Log metrics
elk.log_metric(&metric);
elk.log_tls_metrics(&tls_metrics);

// Log security events
elk.log_security_event(&event);

// Flush buffer
elk.flush();

// Generate Kibana dashboard link
if let Some(link) = elk.kibana_dashboard_link() {
    println!("Dashboard: {}", link);
}
```

## Configuration

### Monitoring Configuration

```rust
use arc_tls::monitoring::*;

let config = MonitoringConfig::builder()
    .enabled(true)
    .exporter_type(ExporterType::Both)
    .enable_alerts(true)
    .collection_interval(60)
    .enable_performance_monitoring(true)
    .performance_history_size(100)
    .build()?;
```

### Prometheus Configuration

```rust
let config = ExporterConfig {
    enabled: true,
    listen_address: "0.0.0.0:9090".to_string(),
    metrics_path: "/metrics".to_string(),
};
```

### ELK Configuration

```rust
let config = ElkConfig {
    enabled: true,
    elasticsearch_url: "http://localhost:9200".to_string(),
    index_prefix: "latticearc-tls".to_string(),
    logstash_url: Some("http://localhost:5044".to_string()),
    kibana_url: Some("http://localhost:5601".to_string()),
    username: Some("elastic".to_string()),
    password: Some("changeme".to_string()),
    enable_tls: true,
};
```

## Default Alert Rules

### Performance Alerts

| Rule Name | Metric | Condition | Threshold | Severity |
|-----------|--------|-----------|-----------|----------|
| `high_handshake_failure_rate` | `handshake_failure_rate` | \> | 5% | Medium |
| `critical_handshake_failure_rate` | `handshake_failure_rate` | \> | 20% | Critical |
| `high_handshake_latency` | `handshake_latency_ms` | \> | 1000ms | High |
| `critical_handshake_latency` | `handshake_latency_ms` | \> | 5000ms | Critical |
| `low_success_rate` | `handshake_success_rate` | \< | 90% | Medium |
| `critical_low_success_rate` | `handshake_success_rate` | \< | 75% | Critical |

### Resource Alerts

| Rule Name | Metric | Condition | Threshold | Severity |
|-----------|--------|-----------|-----------|----------|
| `cpu_exhaustion` | `cpu_usage_percent` | \> | 80% | High |
| `memory_exhaustion` | `memory_usage_mb` | \> | 4096MB | High |
| `high_connection_count` | `active_connections` | \> | 10000 | Medium |

### Security Alerts

| Rule Name | Metric | Condition | Threshold | Severity |
|-----------|--------|-----------|-----------|----------|
| `weak_cipher_suite_detected` | `weak_cipher_suite_count` | \> | 0 | High |
| `tls_version_downgrade` | `tls_version_downgrade_count` | \> | 0 | High |
| `certificate_validation_failures` | `cert_validation_failure_count` | \> | 5 | Medium |
| `brute_force_attempts` | `failed_auth_count` | \> | 10 | Critical |

## Running Examples

### Basic Monitoring

```bash
cargo run --example monitoring_basic --features monitoring
```

### Prometheus Exporter

```bash
cargo run --example monitoring_prometheus --features monitoring
```

### ELK Integration

```bash
cargo run --example monitoring_elk --features monitoring
```

### Alerting System

```bash
cargo run --example monitoring_alerts --features monitoring
```

## Production Deployment

### Prometheus Setup

1. **Install Prometheus**:

```bash
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar -xzf prometheus-2.45.0.linux-amd64.tar.gz
cd prometheus-2.45.0.linux-amd64
```

2. **Configure Prometheus** (`prometheus.yml`):

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'latticearc-tls'
    static_configs:
      - targets: ['localhost:9090']
```

3. **Start Prometheus**:

```bash
./prometheus --config.file=prometheus.yml
```

### ELK Stack Setup

1. **Install Docker**:

```bash
# Install Docker and Docker Compose
```

2. **Create `docker-compose.yml`**:

```yaml
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    ports:
      - "5044:5044"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

volumes:
  esdata:
```

3. **Start ELK Stack**:

```bash
docker-compose up -d
```

4. **Access Kibana**:

```
http://localhost:5601
```

### Monitoring Best Practices

1. **Set Appropriate Thresholds**: Adjust thresholds based on your workload
2. **Use Cooldown Periods**: Prevent alert fatigue
3. **Monitor Trends**: Look for gradual degradation
4. **Alert on Severity**: Route critical alerts appropriately
5. **Regular Review**: Review and update alert rules regularly
6. **Correlate Metrics**: Combine metrics for better insights

## Metrics Reference

### TLS Handshake Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tls_handshake_attempts_total` | Counter | Total handshake attempts |
| `tls_handshake_successes_total` | Counter | Successful handshakes |
| `tls_handshake_failures_total` | Counter | Failed handshakes |
| `tls_handshake_duration_ms` | Histogram | Handshake duration |
| `tls_handshake_success_rate` | Gauge | Success rate percentage |
| `tls_handshake_failure_rate` | Gauge | Failure rate percentage |

### Connection Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tls_active_connections` | Gauge | Current active connections |
| `tls_connections_total` | Counter | Total connections |
| `tls_connection_errors_total` | Counter | Connection errors |

### Key Exchange Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tls_key_exchanges_total` | Counter | Total key exchanges |
| `tls_key_exchange_duration_ms` | Histogram | Key exchange duration |
| `tls_certificate_verifications_total` | Counter | Certificate verifications |
| `tls_cert_verification_duration_ms` | Histogram | Certificate verification duration |

### Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tls_bytes_sent_total` | Counter | Total bytes sent |
| `tls_bytes_received_total` | Counter | Total bytes received |
| `tls_encryption_duration_ms` | Histogram | Encryption duration |
| `tls_decryption_duration_ms` | Histogram | Decryption duration |

### Resource Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tls_cpu_usage_percent` | Gauge | CPU usage percentage |
| `tls_memory_usage_mb` | Gauge | Memory usage in MB |
| `tls_throughput_bytes_per_sec` | Gauge | Throughput in bytes/sec |

## Troubleshooting

### Prometheus Not Scraping

Check if metrics endpoint is accessible:

```bash
curl http://localhost:9090/metrics
```

Verify Prometheus configuration:

```bash
# Check Prometheus targets
http://localhost:9090/targets
```

### ELK Integration Issues

Check Elasticsearch connection:

```bash
curl http://localhost:9200/_cluster/health
```

Check Kibana access:

```
http://localhost:5601
```

### Alert Not Triggering

1. Check if rule is enabled
2. Verify metric name matches
3. Check if cooldown period is active
4. Verify threshold values
5. Check event history for past triggers

## License

Apache License 2.0

## Support

- **Issues**: https://github.com/latticearc/latticearc/issues
- **Documentation**: https://LatticeArc.com/docs/monitoring
- **Security**: Security@LatticeArc.com
