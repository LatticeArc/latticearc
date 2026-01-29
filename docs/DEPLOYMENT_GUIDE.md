# Deployment Guide

This guide covers deploying LatticeArc in production environments.

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | x86_64 or aarch64 | AVX2/NEON support |
| Memory | 64 MB | 256 MB |
| Rust | 1.93+ | Latest stable |

### Supported Platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64 | Fully supported |
| Linux | aarch64 | Fully supported |
| macOS | x86_64 | Fully supported |
| macOS | aarch64 (Apple Silicon) | Fully supported |
| Windows | x86_64 | Fully supported |
| FreeBSD | x86_64 | Best effort |
| WebAssembly | wasm32 | Experimental |

## Build Configuration

### Release Build

```bash
# Optimized release build
cargo build --release --workspace --all-features

# With LTO for maximum optimization
RUSTFLAGS="-C lto=fat" cargo build --release --workspace
```

### Cargo.toml Settings

```toml
[profile.release]
lto = "thin"
codegen-units = 1
panic = "abort"
strip = true

[profile.release-with-debug]
inherits = "release"
debug = true
strip = false
```

### Feature Selection

Only enable features you need:

```toml
[dependencies]
# Minimal: core crypto only
latticearc = "0.1"

# With TLS support
latticearc = { version = "0.1", features = ["tls"] }

# With hybrid encryption
latticearc = { version = "0.1", features = ["hybrid"] }

# All features (not recommended for production)
latticearc = { version = "0.1", features = ["full"] }
```

## Security Hardening

### Memory Protection

```rust
use latticearc::prelude::*;

// Enable memory locking to prevent swapping secrets
#[cfg(unix)]
fn lock_memory() {
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

// Disable core dumps
#[cfg(unix)]
fn disable_core_dumps() {
    unsafe {
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}
```

### Process Isolation

On Linux, consider using seccomp:

```rust
// Restrict system calls to minimum required
// Only allow: read, write, mmap, munmap, exit, etc.
```

### File Permissions

```bash
# Key files should be readable only by the service user
chmod 600 /path/to/private_key.pem
chown service_user:service_group /path/to/private_key.pem
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LATTICEARC_LOG_LEVEL` | Logging verbosity | `warn` |
| `LATTICEARC_DISABLE_HARDWARE_ACCEL` | Force software fallback | `false` |

**Warning**: Never store secrets in environment variables.

### Runtime Configuration

```rust
use latticearc::config::*;

let config = LatticeArcConfig::builder()
    .log_level(LogLevel::Warn)
    .hardware_acceleration(true)
    .memory_limit(256 * 1024 * 1024)  // 256 MB
    .build()?;

latticearc::init(config)?;
```

## Monitoring

### Health Checks

```rust
use latticearc::health::*;

async fn health_check() -> HealthStatus {
    let status = latticearc::health_check().await;

    HealthStatus {
        crypto_available: status.crypto_ok,
        random_available: status.rng_ok,
        memory_ok: status.memory_ok,
    }
}
```

### Metrics

Export metrics for monitoring systems:

```rust
use latticearc::metrics::*;

// Prometheus-compatible metrics
let metrics = latticearc::get_metrics();

println!("latticearc_operations_total {}", metrics.operations);
println!("latticearc_errors_total {}", metrics.errors);
println!("latticearc_key_generations_total {}", metrics.key_generations);
```

### Logging

Configure structured logging:

```rust
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("latticearc=warn"));

    fmt()
        .with_env_filter(filter)
        .json()  // Structured JSON logs
        .with_target(true)
        .with_thread_ids(true)
        .init();
}
```

**Important**: Ensure sensitive data is never logged.

## High Availability

### Key Management

```rust
// Load keys from secure storage at startup
let private_key = secure_storage::load_key("signing_key")?;

// Keep keys in memory (locked, non-swappable)
let key_handle = SecureKeyHandle::new(private_key)?;

// Use throughout application lifetime
let signature = key_handle.sign(&message)?;
```

### Graceful Shutdown

```rust
use tokio::signal;

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    // Zeroize all secrets before exit
    latticearc::shutdown();
}
```

### Load Balancing

LatticeArc is stateless and can be load balanced:

- All instances can perform any operation
- No session affinity required
- Keys should be distributed to all instances securely

## Container Deployment

### Docker

```dockerfile
FROM rust:1.93 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/myapp /usr/local/bin/

# Security hardening
RUN useradd -r -s /bin/false appuser
USER appuser

# No secrets in image
ENV LATTICEARC_LOG_LEVEL=warn

ENTRYPOINT ["/usr/local/bin/myapp"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: latticearc-app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        resources:
          requests:
            memory: "128Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
        volumeMounts:
        - name: keys
          mountPath: /secrets
          readOnly: true
      volumes:
      - name: keys
        secret:
          secretName: crypto-keys
```

## Cloud Deployment

### AWS

```hcl
# Use AWS Secrets Manager for key storage
resource "aws_secretsmanager_secret" "crypto_keys" {
  name = "latticearc-keys"
  kms_key_id = aws_kms_key.crypto.arn
}

# Use instance IAM role for access
resource "aws_iam_role_policy" "secrets_access" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.crypto_keys.arn]
    }]
  })
}
```

### GCP

```hcl
# Use Secret Manager
resource "google_secret_manager_secret" "crypto_keys" {
  secret_id = "latticearc-keys"
  replication {
    automatic = true
  }
}

# Grant access via Workload Identity
resource "google_secret_manager_secret_iam_member" "access" {
  secret_id = google_secret_manager_secret.crypto_keys.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app.email}"
}
```

## Performance Tuning

### Thread Pool

```rust
// Configure thread pool for crypto operations
let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(4)  // Match core count
    .max_blocking_threads(16)  // For CPU-intensive crypto
    .enable_all()
    .build()?;
```

### Memory Allocation

Consider using jemalloc for better performance:

```toml
[dependencies]
jemallocator = "0.5"

[features]
jemalloc = ["jemallocator"]
```

```rust
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Slow key generation | No hardware acceleration | Check CPU features, enable AVX2/NEON |
| High memory usage | Key caching | Configure cache limits |
| Random failures | RNG issues | Check `/dev/urandom` availability |

### Debugging

```bash
# Enable debug logging (not for production)
RUST_LOG=latticearc=debug cargo run

# Check for memory leaks
valgrind --leak-check=full ./target/release/myapp

# Profile CPU usage
perf record -g ./target/release/myapp
perf report
```

## Upgrade Procedures

### Minor Version Upgrades

1. Review changelog for breaking changes
2. Update `Cargo.toml` version
3. Run test suite
4. Deploy to staging
5. Monitor for issues
6. Deploy to production

### Major Version Upgrades

1. Review migration guide
2. Test in isolated environment
3. Plan key rotation if needed
4. Staged rollout with monitoring
5. Keep rollback capability

## Compliance Checklist

Before production deployment:

- [ ] Security hardening applied
- [ ] Memory protection enabled
- [ ] Core dumps disabled
- [ ] Logging configured (no secrets)
- [ ] Monitoring in place
- [ ] Key management implemented
- [ ] Graceful shutdown handling
- [ ] Health checks configured
- [ ] Backup procedures documented
- [ ] Incident response plan ready
