# LatticeArc Portable Key Format (LPK v1)

**Version**: 1.0
**Status**: Implemented
**Module**: `latticearc::unified_api::key_format`

## Overview

LPK (LatticeArc Portable Key) is a schema-first, dual-format key serialization
standard for post-quantum cryptographic keys. It supports all LatticeArc key
types — single-algorithm, hybrid (PQ + classical), and symmetric — with typed
extension points for enterprise features.

**Dual format**: One Rust struct, two wire encodings:
- **JSON** — human-readable: CLI display, REST APIs, debugging, key export
- **CBOR** (RFC 8949) — compact binary: wire protocol, database storage, embedded containers

## Design Principles

1. **Schema-first**: The Rust `PortableKey` struct is the single source of truth. Both JSON and CBOR are serialization targets.
2. **Standards-aligned**: Algorithm identifiers from FIPS 203–206, RFC 7748, RFC 8032. OIDs from RFC 9881 (ML-DSA) and RFC 9935 (ML-KEM). Composite layout follows `draft-ietf-lamps-pq-composite-kem`.
3. **Extensible metadata**: A `BTreeMap<String, Value>` map for enterprise extensions. Enterprise crates add typed accessor traits without modifying the base type. The library preserves all metadata during roundtrips.
5. **Security by default**: Secret/symmetric key material zeroized on drop. Manual `Debug` redacts secrets. File I/O enforces 0600 permissions.

## Key Identity Model

Keys are identified by **use case** or **security level** — mirroring how the
library's API works. Users pick a use case (`FileStorage`, `SecureMessaging`) or
a security level (`Standard`, `High`, `Maximum`), and the library's
policy engine selects the optimal algorithm. At least one must be present.

If both are set, **security level takes precedence** for algorithm resolution
(matching `CryptoConfig` behavior).

The resolved algorithm is stored internally for version-stability — if the
policy engine mapping changes in a future library release, existing key files
still parse correctly. Users never specify algorithms directly.

## Key Layout Diagrams

### Symmetric Key (AES-256)

```
┌─────────────────────────────────────────────┐
│  PortableKey (JSON)                         │
├─────────────────────────────────────────────┤
│  version: 1                                 │
│  algorithm: "aes-256"                       │
│  key_type: "symmetric"                      │
│  key_data:                                  │
│    ┌───────────────────────────────────┐    │
│    │  raw: [32 bytes AES key, base64]  │    │
│    └───────────────────────────────────┘    │
│  created: "2026-04-09T..."                  │
└─────────────────────────────────────────────┘
```

### Hybrid KEM Public Key (ML-KEM-768 + X25519)

```
┌─────────────────────────────────────────────┐
│  PortableKey (JSON)                         │
├─────────────────────────────────────────────┤
│  version: 1                                 │
│  algorithm: "hybrid-ml-kem-768-x25519"      │
│  key_type: "public"                         │
│  key_data:                                  │
│    ┌───────────────────────────────────┐    │
│    │  pq: [1184 bytes ML-KEM PK, b64]  │    │
│    │  classical: [32 bytes X25519, b64] │    │
│    └───────────────────────────────────┘    │
│  created: "2026-04-09T..."                  │
└─────────────────────────────────────────────┘
```

### Hybrid KEM Secret Key (self-contained for decryption)

```
┌──────────────────────────────────────────────────┐
│  PortableKey (JSON)                              │
├──────────────────────────────────────────────────┤
│  version: 1                                      │
│  algorithm: "hybrid-ml-kem-768-x25519"           │
│  key_type: "secret"                              │
│  key_data:                                       │
│    ┌────────────────────────────────────────┐    │
│    │  pq: [2400 bytes ML-KEM SK, base64]    │    │
│    │  classical: [32 bytes X25519 seed, b64] │    │
│    └────────────────────────────────────────┘    │
│  metadata:                                       │
│    ┌────────────────────────────────────────┐    │
│    │  ml_kem_pk: [1184 bytes ML-KEM PK, b64] │    │
│    └────────────────────────────────────────┘    │
│  created: "2026-04-09T..."                       │
│                                                  │
│  ┌──────────────────────────────────────────┐    │
│  │ WHY ml_kem_pk in metadata?               │    │
│  │                                          │    │
│  │ ML-KEM decapsulation (aws-lc-rs) needs   │    │
│  │ both SK + PK bytes to reconstruct the    │    │
│  │ DecapsulationKey. Storing PK here makes   │    │
│  │ the secret key file self-contained —     │    │
│  │ no separate public key file needed for   │    │
│  │ decryption. Follows PKCS#12 pattern.     │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

### Encrypt / Decrypt Flow

```
ENCRYPT (sender has public key only):

  ┌──────────┐    ┌─────────────┐    ┌───────────────────┐
  │ Plaintext │───▶│ encrypt()   │───▶│ EncryptedOutput   │
  └──────────┘    │             │    │  (JSON file)      │
                  │ Public Key  │    │                   │
  ┌──────────┐   │ (.pub.json) │    │  scheme           │
  │ PK file  │──▶│             │    │  ciphertext       │
  └──────────┘    └─────────────┘    │  nonce + tag      │
                                     │  hybrid_data:     │
                                     │    ml_kem_ct      │
                                     │    ecdh_eph_pk    │
                                     └───────────────────┘

DECRYPT (recipient has secret key only):

  ┌───────────────────┐    ┌─────────────┐    ┌──────────┐
  │ EncryptedOutput   │───▶│ decrypt()   │───▶│ Plaintext │
  │  (JSON file)      │    │             │    └──────────┘
  └───────────────────┘    │ Secret Key  │
                           │ (.sec.json) │
  ┌──────────┐             │             │
  │ SK file  │────────────▶│ Contains:   │
  │ (secret  │             │  ML-KEM SK  │
  │  key     │             │  X25519 seed│
  │  only)   │             │  ML-KEM PK  │ ◀── from metadata
  └──────────┘             │  (in metadata)│
                           └─────────────┘

  No public key file needed ✓
```

### Signing Key Layout (Ed25519 / ML-DSA / Hybrid)

```
  KEYGEN                     SIGN                      VERIFY
  ──────                     ────                      ──────

  ┌──────────┐              ┌──────────┐             ┌──────────┐
  │ .pub.json│─── publish ─▶│ Verifier │             │ Verifier │
  │ (public) │              │ receives │             │ checks   │
  └──────────┘              │ pub key  │             │ sig file │
                            └──────────┘             └──────────┘
  ┌──────────┐              ┌──────────┐    sig.json  ┌──────────┐
  │ .sec.json│─── sign() ─▶│ sig.json │──── send ──▶│ verify() │
  │ (secret) │              │ signature│             │ ✓ or ✗   │
  └──────────┘              └──────────┘             └──────────┘
```

## JSON Schema

### Key Created by Use Case

```json
{
  "version": 1,
  "use_case": "file-storage",
  "algorithm": "hybrid-ml-kem-1024-x25519",
  "key_type": "public",
  "key_data": {
    "pq": "Base64-ML-KEM-1024-public-key...",
    "classical": "Base64-X25519-public-key..."
  },
  "created": "2026-03-19T14:30:00Z"
}
```

### Key Created by Security Level

```json
{
  "version": 1,
  "security_level": "high",
  "algorithm": "hybrid-ml-kem-768-x25519",
  "key_type": "secret",
  "key_data": {
    "pq": "Base64-ML-KEM-secret-key...",
    "classical": "Base64-X25519-seed..."
  },
  "created": "2026-03-19T14:30:00Z",
  "metadata": {
    "ml_kem_pk": "Base64-ML-KEM-public-key..."
  }
}
```

> **Note (v0.5.1)**: Hybrid KEM secret key files include the ML-KEM public key
> in metadata, making the secret key file self-contained for decryption. This
> follows the PKCS#12 pattern of bundling public + private material. The public
> key is needed to reconstruct the `MlKemDecapsulationKeyPair` for decapsulation.
> Secret key files generated before v0.5.1 are missing this field and will
> produce an error — regenerate the keypair with the updated CLI or library.

### Key with Enterprise Metadata

```json
{
  "version": 1,
  "algorithm": "aes-256",
  "key_type": "symmetric",
  "key_data": {
    "raw": "Base64-AES-key..."
  },
  "created": "2026-03-19T14:30:00Z",
  "metadata": {
    "label": "Production DEK",
    "compliance_level": "FIPS-140-3"
  }
}
```

## CBOR Format

Same logical schema as JSON. Key differences:
- Key material stored as CBOR byte strings (`bstr`) — no base64 encoding
- Integer-friendly field encoding via serde
- Timestamps as ISO 8601 strings (same as JSON, for serde compatibility)

CBOR is the recommended format for:
- Wire protocol between services
- Database storage
- Embedded containers (encrypted blobs)
- Constrained environments

## Field Reference

### Core Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | `u32` | Yes | Format version. Currently `1`. |
| `use_case` | `UseCase` | At least one of `use_case` or `security_level` | Use case that determined algorithm selection. |
| `security_level` | `SecurityLevel` | At least one of `use_case` or `security_level` | NIST security level (`standard`, `high`, `maximum`). For PQ-only, use `maximum` with `CryptoMode::PqOnly` (the `quantum` variant was removed in 0.7.0). Takes precedence if both present. |
| `algorithm` | `KeyAlgorithm` | Yes (auto-derived) | Resolved algorithm. Auto-populated from `use_case`/`security_level`. Stored for version-stability. |
| `key_type` | `KeyType` | Yes | `"public"`, `"secret"`, or `"symmetric"`. |
| `key_data` | `KeyData` | Yes | Key material — single (`raw`) or composite (`pq` + `classical`). |
| `created` | `DateTime<Utc>` | Yes | ISO 8601 creation timestamp. |

### Extension Fields (optional, omitted when empty)

| Field | Type | Description |
|-------|------|-------------|
| `metadata` | `Map<String, Value>` | Open map for enterprise extensions. Enterprise crates store additional fields (expiry, hardware binding, etc.) here via typed accessor traits. The base library preserves all entries during roundtrips. |

## Algorithm Resolution

### SecurityLevel → Algorithm

| SecurityLevel | Resolved Algorithm | NIST Level |
|---------------|-------------------|------------|
| `standard` | `hybrid-ml-kem-512-x25519` | Level 1 (128-bit) |
| `high` | `hybrid-ml-kem-768-x25519` | Level 3 (192-bit) |
| `maximum` | `hybrid-ml-kem-1024-x25519` | Level 5 (256-bit) |

> The `quantum` variant was removed in 0.7.0. For PQ-only Level 5, use
> `SecurityLevel::Maximum` with `CryptoMode::PqOnly`, which resolves to
> `ml-kem-1024`.

> **PQ-only keys (0.6.0+):** When `CryptoMode::PqOnly` is used, the resolved algorithm
> is `ml-kem-512`, `ml-kem-768`, or `ml-kem-1024` (no X25519 component). The key format
> uses `KeyData::Single` (not `Composite`) since there is no classical key component.

### UseCase → Algorithm

| Use Cases | Resolved Algorithm |
|-----------|--------------------|
| `iot-device` | `hybrid-ml-kem-512-x25519` |
| `secure-messaging`, `vpn-tunnel`, `api-security`, `database-encryption`, `config-secrets`, `session-token`, `audit-log`, `authentication`, `financial-transactions`, `blockchain-transaction`, `firmware-signing`, `digital-certificate`, `legal-documents` | `hybrid-ml-kem-768-x25519` |
| `email-encryption`, `file-storage`, `cloud-storage`, `backup-archive`, `key-exchange`, `healthcare-records`, `government-classified`, `payment-card` | `hybrid-ml-kem-1024-x25519` |

## Supported Algorithms

### Key Encapsulation (FIPS 203)

| Identifier | Standard | OID (RFC 9935) | PK Size | SK Size |
|------------|----------|----------------|---------|---------|
| `ml-kem-512` | FIPS 203 Level 1 | 2.16.840.1.101.3.4.4.1 | 800 B | 1,632 B |
| `ml-kem-768` | FIPS 203 Level 3 | 2.16.840.1.101.3.4.4.2 | 1,184 B | 2,400 B |
| `ml-kem-1024` | FIPS 203 Level 5 | 2.16.840.1.101.3.4.4.3 | 1,568 B | 3,168 B |

### Digital Signatures (FIPS 204)

| Identifier | Standard | OID (RFC 9881) | PK Size | SK Size |
|------------|----------|----------------|---------|---------|
| `ml-dsa-44` | FIPS 204 Level 2 | 2.16.840.1.101.3.4.3.17 | 1,312 B | 2,560 B |
| `ml-dsa-65` | FIPS 204 Level 3 | 2.16.840.1.101.3.4.3.18 | 1,952 B | 4,032 B |
| `ml-dsa-87` | FIPS 204 Level 5 | 2.16.840.1.101.3.4.3.19 | 2,592 B | 4,896 B |

### Hash-Based Signatures (FIPS 205)

| Identifier | Standard | PK Size | SK Size |
|------------|----------|---------|---------|
| `slh-dsa-shake-128s` | FIPS 205 | 32 B | 64 B |
| `slh-dsa-shake-256f` | FIPS 205 | 64 B | 128 B |

### Lattice Signatures (draft FIPS 206)

| Identifier | Standard | PK Size | SK Size |
|------------|----------|---------|---------|
| `fn-dsa-512` | draft FIPS 206 | 897 B | 1,281 B |
| `fn-dsa-1024` | draft FIPS 206 | 1,793 B | 2,305 B |

### Classical

| Identifier | Standard | PK Size | SK Size |
|------------|----------|---------|---------|
| `ed25519` | RFC 8032 | 32 B | 32 B |
| `x25519` | RFC 7748 | 32 B | 32 B |
| `aes-256` | FIPS 197 | — | 32 B |
| `chacha20` | RFC 8439 | — | 32 B |

### Hybrid KEM

| Identifier | Components | PK Size | SK Size |
|------------|-----------|---------|---------|
| `hybrid-ml-kem-512-x25519` | ML-KEM-512 + X25519 | 832 B | 1,664 B |
| `hybrid-ml-kem-768-x25519` | ML-KEM-768 + X25519 | 1,216 B | 2,432 B |
| `hybrid-ml-kem-1024-x25519` | ML-KEM-1024 + X25519 | 1,600 B | 3,200 B |

### Hybrid Signatures

| Identifier | Components | PK Size | SK Size |
|------------|-----------|---------|---------|
| `hybrid-ml-dsa-44-ed25519` | ML-DSA-44 + Ed25519 | 1,344 B | 2,592 B |
| `hybrid-ml-dsa-65-ed25519` | ML-DSA-65 + Ed25519 | 1,984 B | 4,064 B |
| `hybrid-ml-dsa-87-ed25519` | ML-DSA-87 + Ed25519 | 2,624 B | 4,928 B |

## Serialization Size Comparison

For an ML-KEM-768 public key (1,184 raw bytes):

| Format | Envelope | Key Encoding | Total | Overhead |
|--------|----------|-------------|-------|----------|
| **CBOR** | ~30 B | raw bstr | ~1,214 B | +2.5% |
| **JSON** | ~120 B | base64 (1,580 chars) | ~1,700 B | +43.6% |

For large hybrid keys (ML-DSA-87 + Ed25519, 4,928 raw bytes SK):

| Format | Total | Overhead |
|--------|-------|----------|
| **CBOR** | ~4,960 B | +0.6% |
| **JSON** | ~6,700 B | +35.9% |

## Validation Rules

`PortableKey::validate()` enforces:

1. **Symmetric ↔ key type**: `aes-256` and `chacha20` require `KeyType::Symmetric`; non-symmetric algorithms reject `Symmetric` key type.
2. **Hybrid ↔ composite data**: Hybrid algorithms require composite `KeyData` (`pq` + `classical`); non-hybrid algorithms require single `KeyData` (`raw`).
3. **Base64 integrity**: All base64-encoded fields decode successfully.

## Security Properties

- **Zeroization**: All `KeyData` fields are zeroized on drop via `zeroize` crate. `DimensionComponent::key_component` is also zeroized.
- **Debug redaction**: `Debug` impl prints `[REDACTED]` for secret/symmetric keys.
- **File permissions**: `write_to_file()` and `write_cbor_to_file()` set 0600 permissions on Unix for secret/symmetric keys.
- **No unsafe code**: Module-level `#![deny(unsafe_code)]`.

## Rust API

```rust
use latticearc::{PortableKey, KeyType, KeyData, UseCase, SecurityLevel};

// Create by use case (recommended — mirrors library API)
let key = PortableKey::for_use_case(
    UseCase::FileStorage,
    KeyType::Public,
    KeyData::from_raw(&pk_bytes),
);

// Create by security level
let key = PortableKey::for_security_level(
    SecurityLevel::High,
    KeyType::Public,
    KeyData::from_raw(&pk_bytes),
);

// Both (security_level takes precedence for algorithm resolution)
let key = PortableKey::for_use_case_with_level(
    UseCase::FileStorage,
    SecurityLevel::Maximum,
    KeyType::Public,
    KeyData::from_raw(&pk_bytes),
);

// JSON
let json = key.to_json()?;
let restored = PortableKey::from_json(&json)?;

// CBOR
let cbor = key.to_cbor()?;
let restored = PortableKey::from_cbor(&cbor)?;

// File I/O
key.write_to_file(Path::new("key.json"))?;
key.write_cbor_to_file(Path::new("key.cbor"))?;
let loaded = PortableKey::read_from_file(Path::new("key.json"))?;
let loaded = PortableKey::read_cbor_from_file(Path::new("key.cbor"))?;

// Legacy CLI format
let old = PortableKey::from_legacy_json(&cli_v1_json)?;

// Enterprise metadata (preserved during roundtrips)
key.set_label("Production signing key");
key.set_metadata("compliance".into(), serde_json::json!("FIPS-140-3"));
```

## Standards Reference

| Standard | Relevance |
|----------|-----------|
| FIPS 203 (ML-KEM) | Algorithm parameter sets, key sizes |
| FIPS 204 (ML-DSA) | Algorithm parameter sets, key sizes |
| FIPS 205 (SLH-DSA) | Algorithm parameter sets |
| draft FIPS 206 (FN-DSA) | Algorithm parameter sets |
| RFC 8949 (CBOR) | Binary serialization format |
| RFC 9881 (ML-DSA in X.509) | OIDs, seed-only private key format |
| RFC 9935 (ML-KEM in X.509) | OIDs, seed-only private key format |
| draft-ietf-jose-pqc-kem | JWK `"AKP"` key type for ML-KEM |
| draft-ietf-cose-dilithium | COSE `kty=7` for ML-DSA/ML-KEM |
| draft-ietf-lamps-pq-composite-kem | Composite key concatenation |
| RFC 7748 (X25519) | Classical ECDH key exchange |
| RFC 8032 (Ed25519) | Classical digital signatures |

## Enterprise Extension Model

Enterprise crates extend `PortableKey` via Rust extension traits — no base
library modifications needed:

```rust
// Enterprise crate — typed accessors over the metadata map
trait EnterpriseKeyExt {
    fn key_expiry(&self) -> Option<DateTime<Utc>>;
    fn hsm_slot(&self) -> Option<&str>;
    fn dimensions(&self) -> Option<Vec<String>>;
}

impl EnterpriseKeyExt for PortableKey {
    fn key_expiry(&self) -> Option<DateTime<Utc>> {
        self.metadata().get("expires")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
    }
    // ...
}
```

The base library preserves all metadata during roundtrips — enterprise fields
added by extension crates survive serialization through the open-source library.

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-04-09 | Hybrid KEM secret keys now include `ml_kem_pk` in metadata for self-contained decryption. `to_hybrid_secret_key()` no longer requires a separate public key. |
| 1 | 2026-03-19 | Initial release. JSON + CBOR dual format. UseCase/SecurityLevel-first design. |
