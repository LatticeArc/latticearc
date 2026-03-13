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
[releases page](https://github.com/ArcTechnologies-AI/latticearc/releases):

| Platform | Architecture | File |
|----------|-------------|------|
| Linux | x86_64 | `latticearc-linux-x86_64` |
| Linux | ARM64 | `latticearc-linux-aarch64` |
| macOS | Intel | `latticearc-macos-x86_64` |
| macOS | Apple Silicon | `latticearc-macos-aarch64` |
| Windows | x86_64 | `latticearc-windows-x86_64.exe` |

```bash
# macOS/Linux: make it executable and move to your PATH
chmod +x latticearc-macos-aarch64
sudo mv latticearc-macos-aarch64 /usr/local/bin/latticearc

# Verify installation
latticearc info
```

### From Source

Requires Rust 1.93+ and a C compiler (for aws-lc-rs):

```bash
cargo install --path .
```

## Quick Start

### 1. Generate a Signing Key

```bash
latticearc keygen --algorithm ml-dsa65 --output ./keys
```

This creates two files:
- `keys/ml-dsa-65.pub.json` — Public key (share freely)
- `keys/ml-dsa-65.sec.json` — Secret key (keep private, auto-set to 0600 permissions)

### 2. Sign a Document

```bash
latticearc sign --algorithm ml-dsa65 \
  --input contract.pdf \
  --key keys/ml-dsa-65.sec.json
```

Creates `contract.pdf.sig.json` containing the digital signature.

### 3. Verify a Signature

```bash
latticearc verify \
  --input contract.pdf \
  --signature contract.pdf.sig.json \
  --key keys/ml-dsa-65.pub.json
```

Output: `Signature is VALID.`

### 4. Encrypt a File

```bash
# Generate a symmetric key
latticearc keygen --algorithm aes256 --output ./keys

# Encrypt
latticearc encrypt --mode aes256-gcm \
  --input secrets.txt \
  --output secrets.enc.json \
  --key keys/aes256.key.json

# Decrypt
latticearc decrypt \
  --input secrets.enc.json \
  --output secrets.txt \
  --key keys/aes256.key.json
```

### 5. Hash a File

```bash
latticearc hash --algorithm sha-256 --input document.pdf
# Output: SHA-256: a1b2c3d4e5f6...
```

## Commands

### `keygen` — Generate Keys

Creates cryptographic keys for signing, encryption, or key exchange.

```
latticearc keygen --algorithm <ALGORITHM> [--output <DIR>] [--label <TEXT>]
```

**Algorithms:**

| Algorithm | Type | Standard | Use Case |
|-----------|------|----------|----------|
| `aes256` | Symmetric | FIPS 197 | File encryption |
| `ml-kem512` | KEM | FIPS 203 | Key exchange (fast) |
| `ml-kem768` | KEM | FIPS 203 | Key exchange (default) |
| `ml-kem1024` | KEM | FIPS 203 | Key exchange (highest security) |
| `ml-dsa44` | Signature | FIPS 204 | Signing (fast) |
| `ml-dsa65` | Signature | FIPS 204 | Signing (default, recommended) |
| `ml-dsa87` | Signature | FIPS 204 | Signing (highest security) |
| `slh-dsa128s` | Signature | FIPS 205 | Signing (hash-based, conservative) |
| `fn-dsa512` | Signature | FIPS 206 (draft) | Signing (compact signatures) |
| `ed25519` | Signature | RFC 8032 | Signing (classical, fast) |
| `hybrid` | KEM | FIPS 203 + X25519 | Hybrid encryption |
| `hybrid-sign` | Signature | FIPS 204 + RFC 8032 | Hybrid signing (PQ + classical) |

**Which algorithm should I use?**

- **Signing documents?** Use `ml-dsa65` — it's the NIST default, quantum-resistant,
  and widely supported.
- **Need maximum security?** Use `ml-dsa87` (NIST Category 5, equivalent to AES-256).
- **Need backward compatibility?** Use `hybrid-sign` — signs with BOTH ML-DSA-65
  (quantum-safe) AND Ed25519 (classical). If either algorithm is ever broken, the
  other still protects you.
- **Encrypting files?** Use `aes256` for symmetric encryption (you share the key
  securely out-of-band).
- **Firmware/IoT?** Use `fn-dsa512` for compact signatures that save bandwidth.
- **Worried about unknown future attacks?** Use `slh-dsa128s` — it's based purely
  on hash functions, so its security relies only on the hash being collision-resistant
  (the most conservative assumption possible).

**Output files:**

| Key Type | Filename Pattern | Permissions |
|----------|-----------------|-------------|
| Public key | `<algorithm>.pub.json` | World-readable |
| Secret key | `<algorithm>.sec.json` | Owner-only (0600) |
| Symmetric key | `aes256.key.json` | Owner-only (0600) |

**Example:**

```bash
# Generate keys with a human-readable label
latticearc keygen --algorithm ml-dsa65 --output ./keys --label "Production CI/CD"
```

### `sign` — Sign Data

Creates a digital signature proving a file hasn't been tampered with and was
signed by the owner of the secret key.

```
latticearc sign --algorithm <ALGORITHM> --input <FILE> --key <SECRET_KEY>
                [--output <FILE>]
```

**Algorithms:** `ml-dsa65`, `ml-dsa44`, `ml-dsa87`, `slh-dsa`, `fn-dsa`, `ed25519`, `hybrid`

If `--output` is omitted, the signature is written to `<input>.sig.json`.

**Example:**

```bash
# Sign a firmware binary with the strongest post-quantum algorithm
latticearc sign --algorithm ml-dsa87 \
  --input firmware-v3.2.bin \
  --key keys/ml-dsa-87.sec.json \
  --output firmware-v3.2.sig.json
```

**Signature file format (JSON):**

```json
{
  "algorithm": "ml-dsa-65",
  "signature": "Base64EncodedSignatureBytes..."
}
```

For hybrid signatures, the file contains both signature components:

```json
{
  "algorithm": "hybrid-ml-dsa-65-ed25519",
  "ml_dsa_sig": "Base64...",
  "ed25519_sig": "Base64..."
}
```

### `verify` — Verify a Signature

Checks whether a signature is valid for a given file and public key. Returns
exit code 0 if valid, non-zero if invalid.

```
latticearc verify --input <FILE> --signature <SIG_FILE> --key <PUBLIC_KEY>
                  [--algorithm <ALGORITHM>]
```

The `--algorithm` flag is **optional** — the algorithm is automatically detected
from the signature file's `"algorithm"` field.

**Example:**

```bash
# Verify (algorithm auto-detected from signature file)
latticearc verify \
  --input firmware-v3.2.bin \
  --signature firmware-v3.2.sig.json \
  --key keys/ml-dsa-65.pub.json
```

**Exit codes:**
- `0` — Signature is VALID
- `1` — Signature is INVALID (tampered, wrong key, or corrupted)

### `encrypt` — Encrypt Data

Encrypts a file using authenticated encryption (AES-256-GCM). The encrypted
output is a self-contained JSON file.

```
latticearc encrypt --mode <MODE> --input <FILE> --key <KEY_FILE>
                   [--output <FILE>]
```

**Modes:**

| Mode | Algorithm | Key Type | Standard |
|------|-----------|----------|----------|
| `aes256-gcm` | AES-256-GCM | Symmetric | SP 800-38D |
| `hybrid` | ML-KEM-768 + X25519 + AES-256-GCM | Public | FIPS 203 + RFC 7748 |

**Security properties of AES-256-GCM:**
- **Confidentiality** — data is unreadable without the key
- **Integrity** — any modification is detected (authentication tag)
- **Unique nonces** — each encryption uses a random 12-byte nonce (never reused)

**Example:**

```bash
latticearc encrypt --mode aes256-gcm \
  --input database-backup.sql \
  --output database-backup.enc.json \
  --key keys/aes256.key.json
```

### `decrypt` — Decrypt Data

Decrypts a file previously encrypted with `encrypt`. If the file has been
tampered with, decryption will fail (integrity check).

```
latticearc decrypt --input <ENCRYPTED_FILE> --key <KEY_FILE> [--output <FILE>]
```

If `--output` is omitted, decrypted data is printed to stdout (text) or as hex
(binary).

**Example:**

```bash
latticearc decrypt \
  --input database-backup.enc.json \
  --output database-backup.sql \
  --key keys/aes256.key.json
```

### `hash` — Hash Data

Computes a cryptographic hash (fingerprint) of a file. The hash uniquely
identifies the file contents — even a 1-bit change produces a completely
different hash.

```
latticearc hash --algorithm <ALGORITHM> --input <FILE> [--format <hex|base64>]
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
latticearc hash --input document.pdf

# Hash with SHA-256, base64 output
latticearc hash --algorithm sha-256 --input document.pdf --format base64
```

### `kdf` — Key Derivation

Derives a cryptographic key from input material (a password or existing key).

```
latticearc kdf --algorithm <ALGORITHM> --input <TEXT> --salt <HEX>
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
latticearc kdf --algorithm hkdf \
  --input "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" \
  --salt "000102030405060708090a0b0c" \
  --length 32 \
  --info "encryption-key-v1"
```

**PBKDF2 Example** (derive a key from a password):

```bash
latticearc kdf --algorithm pbkdf2 \
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
latticearc info
```

## Key File Format

All keys are stored as JSON files with the following structure:

```json
{
  "version": 1,
  "algorithm": "ml-dsa-65",
  "key_type": "public",
  "key": "Base64EncodedKeyMaterial...",
  "created": "2026-03-12T10:30:00.000Z",
  "label": "Production signing key"
}
```

| Field | Description |
|-------|-------------|
| `version` | File format version (always `1`) |
| `algorithm` | Algorithm identifier (e.g., `ml-dsa-65`, `aes-256`) |
| `key_type` | `public`, `secret`, or `symmetric` |
| `key` | Base64-encoded raw key bytes |
| `created` | ISO 8601 timestamp of key generation |
| `label` | Optional human-readable description |

**Security features:**
- Secret and symmetric key files are created with **0600 permissions** (owner-only) on Unix
- Key material is **zeroized from memory** when no longer needed (FIPS 140-3 compliance)
- Secret key `Debug` output **redacts** the key material (shows `[REDACTED]`)

## Real-World Workflows

### Code Signing (CI/CD)

Protect software releases from tampering:

```bash
# One-time setup: generate a signing key
latticearc keygen --algorithm ml-dsa65 --output ./ci-keys \
  --label "CI/CD Release Signing"

# In your CI pipeline: sign the release artifact
latticearc hash --algorithm sha-256 --input app-v2.0.tar.gz
latticearc sign --algorithm ml-dsa65 \
  --input app-v2.0.tar.gz \
  --key ci-keys/ml-dsa-65.sec.json

# Users verify the download
latticearc verify \
  --input app-v2.0.tar.gz \
  --signature app-v2.0.tar.gz.sig.json \
  --key ci-keys/ml-dsa-65.pub.json
```

### Encrypted Configuration Files

Store secrets safely in version control:

```bash
# Generate an encryption key (store in a secure vault, not in git!)
latticearc keygen --algorithm aes256 --output ./vault \
  --label "Production Config Key"

# Encrypt config before committing
latticearc encrypt --mode aes256-gcm \
  --input config/secrets.json \
  --output config/secrets.enc.json \
  --key vault/aes256.key.json

# Decrypt at deployment time
latticearc decrypt \
  --input config/secrets.enc.json \
  --output config/secrets.json \
  --key vault/aes256.key.json
```

### Document Notarization (Hybrid)

For legal documents that need to remain valid for decades:

```bash
# Generate a hybrid key (quantum-safe + classical fallback)
latticearc keygen --algorithm hybrid-sign --output ./notary \
  --label "Notary 2026"

# Sign the document with BOTH algorithms
latticearc sign --algorithm hybrid \
  --input deed-of-trust.pdf \
  --key notary/hybrid-sign.sec.json

# Verify — both ML-DSA-65 AND Ed25519 must pass
latticearc verify --algorithm hybrid \
  --input deed-of-trust.pdf \
  --signature deed-of-trust.pdf.sig.json \
  --key notary/hybrid-sign.pub.json
```

## Algorithm Reference

### Key & Signature Sizes

Every value below is verified against the official NIST standard and
enforced by our test suite (68 tests, all passing).

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
| FN-DSA-512 | FIPS 206 (draft) | 897 B | 1,281 B | ~666 B (variable) |
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
| AES-256-GCM | FIPS 197 + SP 800-38D | 32 B key, 12 B nonce, 16 B tag | FIPS validated |
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

The CLI includes 68 integration tests covering:

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
