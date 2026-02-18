# TLS Monitoring (Design Document)

> **Status: NOT IMPLEMENTED** — This document describes planned monitoring capabilities.
> No production monitoring code exists in arc-tls today.

## Current State

arc-tls provides post-quantum TLS 1.3 handshake and session management. It does not include any monitoring, alerting, or metrics collection infrastructure.

## Planned Capabilities

The following are planned for future enterprise releases:

- Metrics collection for TLS handshake success/failure rates
- Latency histograms for key exchange and encryption operations
- Prometheus metrics export
- Security event alerting (failure rate spikes, cipher suite downgrades)

## What Exists Today

- Basic tracing via the `tracing` crate (`arc-tls/src/tracing.rs`)
- Session store with connection tracking (`arc-tls/src/session_store.rs`)
- Error types with categorized failures (`arc-tls/src/error.rs`)

## License

Apache License 2.0
