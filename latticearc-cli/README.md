# LatticeArc CLI

**Post-quantum cryptography from the command line.**

LatticeArc CLI lets you generate keys, encrypt files, sign documents, verify
signatures, hash data, and derive keys — all using the latest NIST-standardized
post-quantum algorithms. No cryptography expertise required.

## What is Post-Quantum Cryptography?

Today's encryption (RSA, ECC) will be broken by quantum computers. NIST has
published new standards — ML-KEM, ML-DSA, SLH-DSA — designed to resist both
classical and quantum attacks. LatticeArc implements these standards so you can
protect your data today against tomorrow's threats.

## Installation

### From Prebuilt Binaries (Recommended)

Download the binary for your platform from the
[releases page](https://github.com/latticearc/latticearc/releases):

| Platform | Architecture | File |
|----------|-------------|------|
| Linux | x86_64 | `latticearc-cli-linux-x86_64` |
| Linux | ARM64 | `latticearc-cli-linux-aarch64` |
| macOS | Intel | `latticearc-cli-macos-x86_64` |
| macOS | Apple Silicon | `latticearc-cli-macos-aarch64` |
| Windows | x86_64 | `latticearc-cli-windows-x86_64.exe` |

```bash
# macOS/Linux: make it executable and move to your PATH
chmod +x latticearc-cli-macos-aarch64
sudo mv latticearc-cli-macos-aarch64 /usr/local/bin/latticearc-cli

# Verify installation
latticearc-cli info
```

### From Source

Requires Rust 1.93+ and a C compiler (for aws-lc-rs):

```bash
cargo install --path .
```

## Quick Start

Express **what you want to do**, not which algorithm to use. The library
selects the optimal post-quantum algorithm automatically.

### 1. Sign a Legal Document

```bash
# Generate keys for legal document signing
latticearc-cli keygen --use-case legal-documents --output ./keys

# Sign (provide both keys for the unified API — embeds PK in signature)
latticearc-cli sign --input contract.pdf \
  --key keys/hybrid-ml-dsa-65-ed25519.sec.json \
  --public-key keys/hybrid-ml-dsa-65-ed25519.pub.json

# Verify (algorithm auto-detected from signature file)
latticearc-cli verify --input contract.pdf \
  --signature contract.pdf.sig.json \
  --key keys/hybrid-ml-dsa-65-ed25519.pub.json
```

### 2. Encrypt Healthcare Records

```bash
# Generate encryption key (symmetric AES-256)
latticearc-cli keygen --algorithm aes256 --output ./keys

# Encrypt
latticearc-cli encrypt --use-case healthcare-records \
  --input patient-records.json \
  --output patient-records.enc.json \
  --key keys/aes256.key.json

# Decrypt
latticearc-cli decrypt \
  --input patient-records.enc.json \
  --output patient-records.json \
  --key keys/aes256.key.json
```

### 3. Hash a File

```bash
latticearc-cli hash --algorithm sha-256 --input document.pdf
# Output: SHA-256: a1b2c3d4e5f6...
```

### Expert Mode

If you need a specific algorithm, use `--algorithm` directly:

```bash
latticearc-cli keygen --algorithm ml-dsa87 --output ./keys
latticearc-cli sign --algorithm ml-dsa87 --input file.bin --key keys/ml-dsa-87.sec.json
```

## Commands

### `keygen` — Generate Keys

Creates cryptographic keys for signing, encryption, or key exchange.

**Recommended** — let the library choose the algorithm:

```
latticearc-cli keygen --use-case <USE_CASE> [--security-level <LEVEL>] [--output <DIR>] [--label <TEXT>]
```

**Expert** — specify the algorithm directly:

```
latticearc-cli keygen --algorithm <ALGORITHM> [--output <DIR>] [--label <TEXT>]
```

**Use cases** (22 available — the library selects optimal algorithms):

| Use Case | What it selects | Security Level |
|----------|----------------|----------------|
| `secure-messaging` | ML-KEM-768 + X25519 (enc), ML-DSA-65 + Ed25519 (sig) | Level 3 |
| `file-storage` | ML-KEM-1024 + X25519 (enc), ML-DSA-87 + Ed25519 (sig) | Level 5 |
| `healthcare-records` | ML-KEM-1024 + X25519 (HIPAA-grade) | Level 5 |
| `iot-device` | ML-KEM-512 + X25519 (resource-constrained) | Level 1 |
| `legal-documents` | ML-DSA-87 + Ed25519 (long-term validity) | Level 5 |
| `financial-transactions` | ML-DSA-65 + Ed25519 (compliance) | Level 3 |
| ... | [22 use cases total](../docs/KEY_FORMAT.md#algorithm-resolution) | |

**Security levels** (override the use case's default):

| Level | What it means |
|-------|--------------|
| `standard` | NIST Level 1 (128-bit equivalent) |
| `high` | NIST Level 3 (192-bit, **default**) |
| `maximum` | NIST Level 5 (256-bit) |
| `quantum` | *Deprecated* — use `maximum` + `--mode pq-only` instead |

**Expert algorithms** (12 available):

| Algorithm | Type | Standard |
|-----------|------|----------|
| `aes256` | Symmetric | FIPS 197 |
| `ml-kem512/768/1024` | KEM | FIPS 203 |
| `ml-dsa44/65/87` | Signature | FIPS 204 |
| `slh-dsa128s` | Signature | FIPS 205 |
| `fn-dsa512` | Signature | draft FIPS 206 |
| `ed25519` | Signature | RFC 8032 |
| `hybrid` | KEM | FIPS 203 + X25519 |
| `hybrid-sign` | Signature | FIPS 204 + RFC 8032 |

**Output files:**

| Key Type | Filename Pattern | Permissions |
|----------|-----------------|-------------|
| Public key | `<algorithm>.pub.json` | World-readable |
| Secret key | `<algorithm>.sec.json` | Owner-only (0600) |
| Symmetric key | `aes256.key.json` | Owner-only (0600) |

**Examples:**

```bash
# Recommended: use-case-driven (library selects optimal algorithm)
latticearc-cli keygen --use-case firmware-signing --output ./keys --label "CI/CD Signing"

# Expert: explicit algorithm
latticearc-cli keygen --algorithm ml-dsa65 --output ./keys --label "Production CI/CD"
```

### `sign` — Sign Data

Creates a digital signature proving a file hasn't been tampered with.

**Recommended** — provide both secret and public key for `SignedData` output:

```
latticearc-cli sign --input <FILE> --key <SECRET_KEY> --public-key <PUBLIC_KEY>
                [--use-case <USE_CASE>] [--output <FILE>]
```

**Expert** — specify algorithm directly:

```
latticearc-cli sign --algorithm <ALGORITHM> --input <FILE> --key <SECRET_KEY>
```

When `--public-key` is provided, the library's `sign_with_key()` API produces a
`SignedData` envelope with scheme metadata, timestamp, and embedded public key.
The `verify` command auto-detects the format.

**Example:**

```bash
# Sign with use-case config (recommended)
latticearc-cli sign --input contract.pdf \
  --key keys/hybrid-ml-dsa-65-ed25519.sec.json \
  --public-key keys/hybrid-ml-dsa-65-ed25519.pub.json \
  --use-case legal-documents
```

### `verify` — Verify a Signature

Checks whether a signature is valid for a given file and public key. Returns
exit code 0 if valid, non-zero if invalid.

```
latticearc-cli verify --input <FILE> --signature <SIG_FILE> --key <PUBLIC_KEY>
                  [--algorithm <ALGORITHM>]
```

The `--algorithm` flag is **optional** — the algorithm is automatically detected
from the signature file's `"algorithm"` field.

**Example:**

```bash
# Verify (algorithm auto-detected from signature file)
latticearc-cli verify \
  --input firmware-v3.2.bin \
  --signature firmware-v3.2.sig.json \
  --key keys/ml-dsa-65.pub.json
```

**Exit codes:**
- `0` — Signature is VALID
- `1` — Signature is INVALID (tampered, wrong key, or corrupted)

### `encrypt` — Encrypt Data

Encrypts a file using authenticated encryption. The encrypted output is a
self-contained JSON file.

**Recommended** — use case-driven:

```
latticearc-cli encrypt --use-case <USE_CASE> --input <FILE> --key <KEY_FILE> [--output <FILE>]
```

**Expert** — specify mode directly:

```
latticearc-cli encrypt --mode <MODE> --input <FILE> --key <KEY_FILE> [--output <FILE>]
```

**Modes:** `aes256-gcm` (symmetric, SP 800-38D), `hybrid` (ML-KEM-768 + X25519 + AES-256-GCM), `pq-only` (ML-KEM + AES-256-GCM, CNSA 2.0), `chacha20-poly1305` (symmetric, RFC 8439)

**Examples:**

```bash
# Symmetric encryption (AES-256-GCM)
latticearc-cli encrypt --key keys/aes256.key.json \
  --input database-backup.sql \
  --output database-backup.enc.json

# Hybrid post-quantum encryption (encrypt with public key)
latticearc-cli keygen --algorithm hybrid --output ./keys
latticearc-cli encrypt --mode hybrid --key keys/hybrid-kem.pub.json \
  --input secret-report.pdf \
  --output secret-report.enc.json

# PQ-only encryption (CNSA 2.0 — no classical component)
latticearc-cli keygen --algorithm ml-kem768 --output ./keys
latticearc-cli encrypt --mode pq-only --key keys/ml-kem-768.pub.json \
  --input classified.pdf \
  --output classified.enc.json
```

### `decrypt` — Decrypt Data

Decrypts a file previously encrypted with `encrypt`. If the file has been
tampered with, decryption will fail (integrity check).

```
latticearc-cli decrypt --input <ENCRYPTED_FILE> --key <KEY_FILE> [--output <FILE>]
```

For **symmetric** decryption, provide the same key used for encryption.
For **hybrid** decryption, provide the **secret key** — the public key is
embedded in the secret key file (no separate public key file needed).

If `--output` is omitted, decrypted data is printed to stdout (text) or as hex
(binary).

**Examples:**

```bash
# Symmetric decrypt
latticearc-cli decrypt \
  --input database-backup.enc.json \
  --output database-backup.sql \
  --key keys/aes256.key.json

# Hybrid post-quantum decrypt (secret key only — public key embedded)
latticearc-cli decrypt \
  --input secret-report.enc.json \
  --output secret-report.pdf \
  --key keys/hybrid-kem.sec.json
```

### `hash` — Hash Data

Computes a cryptographic hash (fingerprint) of a file. The hash uniquely
identifies the file contents — even a 1-bit change produces a completely
different hash.

```
latticearc-cli hash --algorithm <ALGORITHM> --input <FILE> [--format <hex|base64>]
```

**Algorithms:**

| Algorithm | Standard | Output Size | Notes |
|-----------|----------|-------------|-------|
| `sha3-256` | FIPS 202 | 32 bytes | Default. NIST's newest hash family. |
| `sha-256` | FIPS 180-4 | 32 bytes | Widely used (Git, Bitcoin, TLS). |
| `sha-512` | FIPS 180-4 | 64 bytes | Larger output for higher collision resistance. |
| `blake2b` | RFC 7693 | 32 bytes | Fast, modern. Used by Argon2, WireGuard. |

**Example:**

```bash
# Hash a file (default: SHA3-256, hex output)
latticearc-cli hash --input document.pdf

# Hash with SHA-256, base64 output
latticearc-cli hash --algorithm sha-256 --input document.pdf --format base64
```

### `kdf` — Key Derivation

Derives a cryptographic key from input material (a password or existing key).

```
latticearc-cli kdf --algorithm <ALGORITHM> --input <TEXT> --salt <HEX>
               [--length <BYTES>] [--info <TEXT>] [--iterations <N>]
               [--format <hex|base64>]
```

**Algorithms:**

| Algorithm | Standard | Use Case |
|-----------|----------|----------|
| `hkdf` | SP 800-56C / RFC 5869 | Derive keys from existing key material |
| `pbkdf2` | SP 800-132 | Derive keys from passwords |

**HKDF Example** (derive a 32-byte key from existing key material):

```bash
latticearc-cli kdf --algorithm hkdf \
  --input "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" \
  --salt "000102030405060708090a0b0c" \
  --length 32 \
  --info "encryption-key-v1"
```

**PBKDF2 Example** (derive a key from a password):

```bash
latticearc-cli kdf --algorithm pbkdf2 \
  --input "my-strong-password" \
  --salt "73616c7473616c74" \
  --length 32 \
  --iterations 600000
```

> **Note:** For HKDF, `--input` is hex-encoded key material. For PBKDF2,
> `--input` is a plaintext password. The `--salt` is always hex-encoded.

### `info` — System Information

Shows the CLI version, library version, FIPS status, and all supported algorithms.

```bash
latticearc-cli info
```

## Key File Format

Keys are stored using the **LatticeArc Portable Key (LPK)** format — the library's standard
key serialization. Keys are identified by **use case** or **security level** (matching how
the library API works), with the algorithm auto-derived. The CLI writes keys as JSON
(human-readable, `.json` extension) and reads both JSON and CBOR interchangeably, so
CBOR-encoded keys produced by the library API or other LPK tooling load without conversion.

See [`docs/KEY_FORMAT.md`](../docs/KEY_FORMAT.md) for the full specification.

### How Keys Work

```
SYMMETRIC (AES-256):         HYBRID (ML-KEM + X25519):

  ┌──────────┐                 ┌──────────┐  ┌──────────┐
  │ .key.json│                 │ .pub.json│  │ .sec.json│
  │          │                 │          │  │          │
  │ AES key  │                 │ ML-KEM PK│  │ ML-KEM SK│
  │ (32 B)   │                 │ (1184 B) │  │ (2400 B) │
  └──────────┘                 │ X25519 PK│  │ X25519   │
       │                       │ (32 B)   │  │ seed(32B)│
       ▼                       └──────────┘  │ ML-KEM PK│ ◀ in metadata
  encrypt + decrypt              │            │ (1184 B) │
  (same key)                     ▼            └──────────┘
                              encrypt              │
                              (public key)         ▼
                                                decrypt
                                              (secret key only)
```

**Hybrid secret keys are self-contained** — the ML-KEM public key is stored in
the secret key file's metadata, so you only need one file to decrypt.

```json
{
  "version": 1,
  "use_case": "legal-documents",
  "algorithm": "hybrid-ml-dsa-65-ed25519",
  "key_type": "public",
  "key_data": {
    "pq": "Base64-ML-DSA-public-key...",
    "classical": "Base64-Ed25519-public-key..."
  },
  "created": "2026-03-19T10:30:00.000Z",
  "metadata": {
    "label": "Production signing key"
  }
}
```

| Field | Description |
|-------|-------------|
| `version` | Format version (currently `1`) |
| `use_case` | Use case that selected the algorithm (e.g., `file-storage`, `legal-documents`) |
| `security_level` | Alternative to use_case: `standard`, `high`, `maximum`, `quantum` |
| `algorithm` | Auto-derived algorithm (e.g., `hybrid-ml-kem-768-x25519`) |
| `key_type` | `public`, `secret`, or `symmetric` |
| `key_data` | Single (`raw`) or composite (`pq` + `classical`) base64-encoded key bytes |
| `created` | ISO 8601 timestamp of key generation |
| `metadata` | Optional map — `label`, enterprise extensions, etc. |

> The CLI reads both the current LPK format and legacy v1 key files for
> backward compatibility.

**Security features:**
- Secret and symmetric key files are created with **0600 permissions** (owner-only) on Unix
- Key material is **zeroized from memory** when no longer needed
- Secret key `Debug` output **redacts** the key material (shows `[REDACTED]`)

## Real-World Workflows

### Code Signing (CI/CD)

Protect software releases from tampering:

```bash
# One-time setup: generate a signing key for firmware
latticearc-cli keygen --use-case firmware-signing --output ./ci-keys \
  --label "CI/CD Release Signing"

# In your CI pipeline: sign the release artifact
latticearc-cli hash --algorithm sha-256 --input app-v2.0.tar.gz
latticearc-cli sign --input app-v2.0.tar.gz \
  --key ci-keys/hybrid-ml-dsa-65-ed25519.sec.json \
  --public-key ci-keys/hybrid-ml-dsa-65-ed25519.pub.json

# Users verify the download
latticearc-cli verify \
  --input app-v2.0.tar.gz \
  --signature app-v2.0.tar.gz.sig.json \
  --key ci-keys/hybrid-ml-dsa-65-ed25519.pub.json
```

### Encrypted Configuration Files

Store secrets safely in version control:

```bash
# Generate an encryption key (store in a secure vault, not in git!)
latticearc-cli keygen --algorithm aes256 --output ./vault \
  --label "Production Config Key"

# Encrypt config before committing
latticearc-cli encrypt --use-case config-secrets \
  --input config/secrets.json \
  --output config/secrets.enc.json \
  --key vault/aes256.key.json

# Decrypt at deployment time
latticearc-cli decrypt \
  --input config/secrets.enc.json \
  --output config/secrets.json \
  --key vault/aes256.key.json
```

### Document Notarization (Hybrid)

For legal documents that need to remain valid for decades:

```bash
# Generate a hybrid signing key for legal use
latticearc-cli keygen --use-case legal-documents --output ./notary \
  --label "Notary 2026"

# Sign with both ML-DSA-65 AND Ed25519 (unified API)
latticearc-cli sign --input deed-of-trust.pdf \
  --key notary/hybrid-ml-dsa-65-ed25519.sec.json \
  --public-key notary/hybrid-ml-dsa-65-ed25519.pub.json

# Verify — algorithm auto-detected from signature file
latticearc-cli verify \
  --input deed-of-trust.pdf \
  --signature deed-of-trust.pdf.sig.json \
  --key notary/hybrid-ml-dsa-65-ed25519.pub.json
```

## Algorithm Reference

### Key & Signature Sizes

Every value below is verified against the official NIST standard and
enforced by our test suite (83 tests, all passing).

**Digital Signatures (FIPS 204 — ML-DSA):**

| Parameter Set | Security | Public Key | Secret Key | Signature |
|---------------|----------|------------|------------|-----------|
| ML-DSA-44 | Category 2 (128-bit) | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | Category 3 (192-bit) | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | Category 5 (256-bit) | 2,592 B | 4,896 B | 4,627 B |

**Digital Signatures (Other Standards):**

| Algorithm | Standard | Public Key | Secret Key | Signature |
|-----------|----------|------------|------------|-----------|
| SLH-DSA-SHAKE-128s | FIPS 205 | 32 B | 64 B | 7,856 B |
| FN-DSA-512 | draft FIPS 206 | 897 B | 1,281 B | ~666 B (variable) |
| Ed25519 | RFC 8032 | 32 B | 32 B | 64 B |

**Key Encapsulation (FIPS 203 — ML-KEM):**

| Parameter Set | Security | Public Key | Secret Key | Ciphertext |
|---------------|----------|------------|------------|------------|
| ML-KEM-512 | Category 1 (128-bit) | 800 B | 1,632 B | 768 B |
| ML-KEM-768 | Category 3 (192-bit) | 1,184 B | 2,400 B | 1,088 B |
| ML-KEM-1024 | Category 5 (256-bit) | 1,568 B | 3,168 B | 1,568 B |

**Symmetric Encryption & Hashing:**

| Algorithm | Standard | Key/Output Size | Notes |
|-----------|----------|-----------------|-------|
| AES-256-GCM | FIPS 197 + SP 800-38D | 32 B key, 12 B nonce, 16 B tag | Routes through CMVP-validated aws-lc-rs with `--features fips` |
| SHA3-256 | FIPS 202 | 32 B output | |
| SHA-256 | FIPS 180-4 | 32 B output | |
| SHA-512 | FIPS 180-4 | 64 B output | |
| BLAKE2b-256 | RFC 7693 | 32 B output | |
| HKDF-SHA256 | SP 800-56C | 1–8,160 B output | |
| PBKDF2-HMAC-SHA256 | SP 800-132 | configurable | 600,000 iterations default |

## Security Model

### What LatticeArc Protects Against

- **Quantum computer attacks** — All PQC algorithms (ML-KEM, ML-DSA, SLH-DSA,
  FN-DSA) are designed to resist attacks from both classical and quantum computers.
- **Tampered files** — Signatures detect any modification to the signed data.
- **Wrong key usage** — The CLI validates key types (public vs. secret vs. symmetric)
  and algorithm compatibility before performing operations.
- **Ciphertext tampering** — AES-256-GCM's authentication tag detects any
  modification to encrypted data.
- **Key exposure in memory** — Key material is zeroized when no longer needed.
- **File permission mistakes** — Secret keys are automatically restricted to
  owner-only access (0600).

### What LatticeArc Does NOT Protect Against

- **Compromised systems** — If an attacker has access to your machine, they can
  read your secret keys. Use hardware security modules (HSMs) for high-security
  deployments.
- **Key distribution** — You must securely share public keys through a trusted
  channel. The CLI does not include a PKI or certificate authority.
- **Password strength** — When using PBKDF2, choose a strong password. The CLI
  does not enforce password policies.

## Testing

The CLI includes 83 integration tests covering:

- **E2E roundtrips** — keygen → sign → verify, keygen → encrypt → decrypt
- **NIST conformance** — key/signature sizes verified against FIPS 203/204/205/206
- **Edge cases** — empty files, binary data, 1 MB messages
- **Negative tests** — wrong keys, missing arguments, invalid inputs
- **Adversarial scenarios** — bit-flipped ciphertexts/signatures, MITM substitution,
  algorithm field tampering, key isolation matrix

Run the tests:

```bash
cargo test -p latticearc-cli --release -- --nocapture
```

## License

Apache 2.0. See [LICENSE](../LICENSE) for details.

The underlying `latticearc` library is also Apache 2.0 and available on
[crates.io](https://crates.io/crates/latticearc).
