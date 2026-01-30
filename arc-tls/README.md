# LatticeArc TLS

TLS 1.3 implementation with post-quantum key exchange support using rustls.

## Features

- **Hybrid Key Exchange**: X25519MLKEM768 (ECDHE + ML-KEM) for post-quantum security
- **Backward Compatible**: Works with standard TLS 1.3 clients
- **Unified API**: Consistent builder pattern matching `CryptoConfig`
- **Easy API**: Simple client/server connector functions

## Overview

This crate provides TLS 1.3 connectivity with hybrid key exchange combining:
- **X25519**: Classical elliptic curve Diffie-Hellman (ECDH)
- **ML-KEM-768**: Post-quantum key encapsulation mechanism (NIST FIPS 203)

The hybrid approach ensures security even if one component is compromised, while maintaining compatibility with existing TLS 1.3 infrastructure.

## Unified API

`TlsConfig` follows the same builder pattern as `CryptoConfig` for consistency:

```rust
use arc_tls::{TlsConfig, TlsUseCase};
use arc_core::SecurityLevel;

// Both APIs use the same pattern:
// CryptoConfig::new().use_case(UseCase::FileStorage)
// TlsConfig::new().use_case(TlsUseCase::WebServer)

// Default: Hybrid mode
let config = TlsConfig::new();

// Use case-based selection (recommended)
let config = TlsConfig::new()
    .use_case(TlsUseCase::WebServer);

// Security level-based selection
let config = TlsConfig::new()
    .security_level(SecurityLevel::Maximum);
```

## Security

### Hybrid Security Model

The hybrid key exchange (X25519MLKEM768) provides defense-in-depth:

```
Security = min(Security(X25519), Security(ML-KEM-768))
```

An attacker must break BOTH components to compromise the handshake:
- Break X25519: Requires solving discrete logarithm (classical problem)
- Break ML-KEM-768: Requires breaking lattice-based cryptography (quantum-resistant)

### Security Levels

| Mode | Method | PQ Secure | Security Level |
|------|--------|-----------|----------------|
| Classic | X25519 | No | 128-bit (classical) |
| Hybrid | X25519MLKEM768 | Yes | 128-bit + PQ |
| PQ | ML-KEM | Yes | 192-bit (PQ) |

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
arc-tls = "0.1.0"
```

### Feature Flags

- `pq` (default): Enable rustls-post-quantum for hybrid KEX
- `hybrid`: Enable custom hybrid implementation
- `ecc_hybrid`: Enable ECC-based hybrid signatures

## Quick Start

### Client

```rust
use arc_tls::*;

// Default: hybrid mode with PQ key exchange
let stream = tls_connect("example.com:443", "example.com", &TlsConfig::new()).await?;

// Use the stream...
let mut buffer = vec![0u8; 4096];
let n = stream.read(&mut buffer).await?;
```

### Server

```rust
use arc_tls::*;
use tokio::net::TcpListener;

// Create server acceptor (default: hybrid mode)
let acceptor = create_server_acceptor(&TlsConfig::new(), "server.crt", "server.key")?;

// Accept connections
let listener = TcpListener::bind("0.0.0.0:8443").await?;
let (tcp_stream, _) = listener.accept().await?;
let tls_stream = tls_accept(tcp_stream, &acceptor).await?;
```

### Generate Test Certificates

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

## TLS Modes

### Hybrid Mode (Default, Recommended)

Uses X25519MLKEM768 combining X25519 and ML-KEM-768.

```rust
// Default - no configuration needed
let config = TlsConfig::new();

// Or explicitly via security level
let config = TlsConfig::new()
    .security_level(SecurityLevel::High);
```

**Benefits:**
- Post-quantum secure
- Backward compatible
- Fallback to classical if PQ not supported
- Standardized (IETF draft)

**Trade-offs:**
- Larger handshake messages (+~2KB)
- Slower key exchange (~2-3x CPU)
- Negligible impact on overall performance

### Classic Mode

For IoT or legacy systems that need classic TLS (not PQ secure), use a use case:

```rust
let config = TlsConfig::new()
    .use_case(TlsUseCase::IoT);  // or TlsUseCase::LegacyIntegration
```

**Benefits:**
- Smallest handshake size
- Fastest key exchange
- Maximum compatibility

**Trade-offs:**
- Not PQ secure
- Vulnerable to quantum computers

> **Note:** All security levels (Standard, High, Maximum) now use Hybrid mode by default for defense-in-depth. Only `SecurityLevel::Quantum` uses PQ-only mode. Use `TlsUseCase::IoT` or `TlsUseCase::LegacyIntegration` for classic TLS.

### PQ-Only Mode

Post-quantum only with ML-KEM.

```rust
let config = TlsConfig::new()
    .security_level(SecurityLevel::Maximum);
```

**Benefits:**
- Post-quantum secure
- Pure PQ security

**Trade-offs:**
- May have compatibility issues
- No classical fallback
- Pre-standardization

## Use Case-Based Selection

The `TlsPolicyEngine` recommends modes based on your deployment scenario:

```rust
use arc_tls::{TlsConfig, TlsUseCase};

// Create config for specific use case
let config = TlsConfig::new().use_case(TlsUseCase::WebServer);        // -> Hybrid
let config = TlsConfig::new().use_case(TlsUseCase::Government);       // -> PQ
let config = TlsConfig::new().use_case(TlsUseCase::IoT);              // -> Classic
let config = TlsConfig::new().use_case(TlsUseCase::FinancialServices); // -> Hybrid
```

### TlsUseCase Mappings

| TlsUseCase | Mode | Rationale |
|------------|------|-----------|
| `WebServer` | **Hybrid** | Balance security + browser compatibility |
| `ApiGateway` | **Hybrid** | Client compatibility required |
| `InternalService` | **Hybrid** | Zero-trust internal security |
| `FinancialServices` | **Hybrid** | Compliance + PQ protection |
| `Healthcare` | **Hybrid** | HIPAA + future-proofing |
| `Government` | **Pq** | Maximum quantum resistance required |
| `DatabaseConnection` | **Hybrid** | Long-lived, future-proof |
| `IoT` | **Classic** | Resource constraints |
| `LegacyIntegration` | **Classic** | Maximum compatibility |
| `RealTimeStreaming` | **Classic** | Low latency priority |

### Selection Priority

```
┌────────────────────────────────────────────────────────────┐
│                   TLS Mode Selection                       │
├────────────────────────────────────────────────────────────┤
│ 1. Hard constraints (require_compatibility) → Classic      │
│ 2. PQ not available → Classic                              │
│ 3. Use case recommendation (if specified)                  │
│ 4. SecurityLevel::Maximum + constraints allow → Pq         │
│ 5. Default: Hybrid                                         │
└────────────────────────────────────────────────────────────┘
```

## Examples

Run examples with:

```bash
# Hybrid client
cargo run --example tls13_hybrid_client --features pq

# Hybrid server
cargo run --example tls13_hybrid_server --features pq

# Custom hybrid implementation
cargo run --example tls13_custom_hybrid --features hybrid,ecc_hybrid
```

## Performance Impact

### Handshake Message Sizes

| Component | Classic | Hybrid | Increase |
|-----------|---------|--------|----------|
| ClientHello | ~300 bytes | ~1500 bytes | +1200 bytes |
| ServerHello | ~200 bytes | ~1300 bytes | +1100 bytes |

### CPU Overhead

Based on [rustls performance report](https://rustls.dev/perf/2024-12-17-pq-kx/):

| Operation | Classic | Hybrid | Overhead |
|-----------|---------|--------|----------|
| Key Exchange | ~0.3ms | ~0.9ms | +0.6ms |
| Full Handshake | ~1ms | ~1.5ms | +50% |

### Overall Impact

For typical HTTPS requests:
- Key exchange overhead: **negligible** (<1% of total time)
- Connection setup: **minimal** impact
- Data transfer: **no** impact
- TLS record processing: **no** impact

## Builder Pattern Options

`TlsConfig` supports additional builder methods:

```rust
use arc_tls::TlsConfig;

let config = TlsConfig::new()
    .use_case(TlsUseCase::WebServer)
    .with_tracing()                    // Enable tracing
    .with_fallback(true)               // Enable fallback to classical
    .with_client_auth(true)            // Require client certificates
    .with_min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
    .with_max_protocol_version(rustls::ProtocolVersion::TLSv1_3);
```

## Testing

```bash
# Run all tests
cargo test --package arc-tls

# Run with PQ support
cargo test --package arc-tls --features pq

# Run with hybrid support
cargo test --package arc-tls --features hybrid,ecc_hybrid
```

## Handshake Flow

### Classic TLS 1.3

```
Client                                       Server
------                                       ------
ClientHello (X25519 key share)  ---------->
                                        ServerHello (X25519 key share)
                                        EncryptedExtensions
                                        Certificate, CertificateVerify
                                        Finished  <----------
Finished  ---------->
[Application Data]
```

### Hybrid TLS 1.3 (X25519MLKEM768)

```
Client                                       Server
------                                       ------
ClientHello (X25519 + ML-KEM key shares)  ---------->
                                        ServerHello (X25519 + ML-KEM key shares)
                                        EncryptedExtensions
                                        Certificate, CertificateVerify
                                        Finished  <----------
Finished  ---------->
[Application Data]
```

## Implementation Details

### rustls-post-quantum Integration

Uses the [`rustls-post-quantum`](https://crates.io/crates/rustls-post-quantum) crate which provides:

- **X25519MLKEM768**: Hybrid key exchange algorithm
- **Early ML-KEM decapsulation**: Performance optimization
- **Fallback handling**: Graceful degradation to X25519

### Custom Hybrid Implementation

The `arc-hybrid` module provides:

- **ML-KEM-768**: From arc-primitives
- **X25519**: From x25519-dalek
- **HKDF**: NIST SP 800-56C compliant key derivation
- **Zeroization**: Automatic memory clearing

### Cipher Suites

Supports TLS 1.3 cipher suites:
- `TLS_AES_256_GCM_SHA384` (AES-GCM with 256-bit key)
- `TLS_AES_128_GCM_SHA256` (AES-GCM with 128-bit key)
- `TLS_CHACHA20_POLY1305_SHA256` (ChaCha20-Poly1305)

PQ mode prefers ChaCha20 for better performance with ML-KEM.

## Standards Compliance

- **TLS 1.3**: RFC 8446
- **ML-KEM**: NIST FIPS 203
- **X25519MLKEM768**: [IETF draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- **HKDF**: NIST SP 800-56C

## Compatibility

### Client Support

| Client | PQ Support | Fallback |
|--------|------------|----------|
| Chrome 124+ | Yes | X25519 |
| Firefox | Yes | X25519 |
| Safari | Partial | X25519 |
| OpenSSL 3.2+ | Yes | X25519 |
| Go TLS | No | X25519 |

### Server Support

| Server | PQ Support | Fallback |
|--------|------------|----------|
| Cloudflare | Yes | X25519 |
| nginx + rustls | Yes | X25519 |
| Apache | Partial | X25519 |
| Caddy | Yes | X25519 |

## Monitoring and Debugging

### Get Configuration Info

```rust
let config = TlsConfig::new();
println!("Config info: {}", get_config_info(&config));
```

### Get Key Exchange Info

```rust
let kex_info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
println!("Method: {}", kex_info.method);
println!("PQ Secure: {}", kex_info.is_pq_secure);
```

### Check PQ Availability

```rust
if pq_enabled() {
    println!("Post-quantum support is available!");
}
```

## Security Considerations

### Important Notes

1. **Certificate Authentication**: Currently uses classical certificates (RSA/ECDSA). PQ certificate authentication (ML-DSA) is separate from key exchange.

2. **Forward Secrecy**: Hybrid mode maintains forward secrecy via both X25519 and ML-KEM.

3. **Downgrade Attacks**: TLS 1.3 prevents downgrade attacks via the `supported_versions` extension.

4. **Side-Channel Resistance**: Uses constant-time implementations for all cryptographic operations.

5. **Memory Safety**: Automatic zeroization of sensitive material via the `zeroize` crate.

### Deployment Recommendations

1. **Production**: Use Hybrid mode (default)
2. **Testing**: Test with Classic mode for baseline
3. **Compliance**: Monitor NIST/NSA guidance for migration
4. **Rollback**: Always keep Classic mode as fallback

## Troubleshooting

### Connection Fails

If TLS handshake fails:

1. Check if client supports TLS 1.3
2. Verify certificate is valid
3. Try Classic mode for comparison
4. Check firewall allows TLS traffic

### Performance Issues

If performance is slow:

1. Verify PQ mode is actually needed
2. Consider using Classic mode for internal traffic
3. Check if client doesn't support PQ (causes retry)
4. Profile with `tokio-console`

### Feature Not Available

If PQ support is not available:

```bash
cargo build --features pq
```

## License

Apache License 2.0

## References

- [rustls-post-quantum](https://crates.io/crates/rustls-post-quantum)
- [IETF ML-KEM for TLS](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/)
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [rustls PQ Performance](https://rustls.dev/perf/2024-12-17-pq-kx/)
- [LatticeArc Core](../latticearc/README.md)
