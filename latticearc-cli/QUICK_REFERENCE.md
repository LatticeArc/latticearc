# LatticeArc CLI — Quick Reference

## Generate Keys

**Recommended** — express intent, library selects the algorithm:

```bash
latticearc keygen --use-case <USE_CASE> [-o <dir>] [-l <label>]
```

**Expert** — specify algorithm directly:

```bash
latticearc keygen -a <algorithm> -o <dir> [-l <label>]
```

| Use Case | What It Selects |
|----------|----------------|
| `secure-messaging` | ML-KEM-768 + X25519, ML-DSA-65 + Ed25519 |
| `file-storage` | ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519 |
| `healthcare-records` | ML-KEM-1024 + X25519 (HIPAA-grade) |
| `iot-device` | ML-KEM-512 + X25519 (resource-constrained) |
| `legal-documents` | ML-DSA-87 + Ed25519 (long-term validity) |
| `financial-transactions` | ML-DSA-65 + Ed25519 (compliance) |
| `firmware-signing` | ML-DSA-65 + Ed25519 (CI/CD) |
| ... | [22 use cases total](../docs/KEY_FORMAT.md#algorithm-resolution) |

Expert algorithms: `aes256`, `ml-dsa44/65/87`, `ml-kem512/768/1024`, `slh-dsa128s`, `fn-dsa512`, `ed25519`, `hybrid`, `hybrid-sign`

## Sign & Verify

```bash
# Sign (recommended — unified API, embeds PK in signature)
latticearc sign -i <file> -k <secret.json> --public-key <public.json>

# Sign (expert — explicit algorithm)
latticearc sign -a <algorithm> -i <file> -k <secret.json>

# Verify (algorithm auto-detected, PK embedded in SignedData)
latticearc verify -i <file> -s <sig.json>

# Verify (legacy format — requires --key)
latticearc verify -i <file> -s <sig.json> -k <public.json>
```

## Encrypt & Decrypt

```bash
# Encrypt (recommended — use-case-driven)
latticearc encrypt --use-case <USE_CASE> -i <file> -o <enc.json> -k <key.json>

# Encrypt (expert — explicit mode)
latticearc encrypt -m aes256-gcm -i <file> -o <enc.json> -k <key.json>

# Decrypt
latticearc decrypt -i <enc.json> -o <file> -k <key.json>
```

Modes: `aes256-gcm`, `chacha20-poly1305`, `hybrid`

## Hash

```bash
latticearc hash -a <algorithm> -i <file> [-f <hex|base64>]
```

Algorithms: `sha3-256` (default), `sha-256`, `sha-512`, `blake2b`

## Key Derivation

```bash
# From key material (HKDF)
latticearc kdf -a hkdf -i <hex_key> -s <hex_salt> [-l <bytes>] [--info <text>]

# From password (PBKDF2)
latticearc kdf -a pbkdf2 -i <password> -s <hex_salt> [-l <bytes>] [--iterations <n>]
```

## Info

```bash
latticearc info       # Show version, FIPS status, supported algorithms
latticearc --help     # Show all commands
latticearc <cmd> -h   # Show help for a specific command
```

## Common Workflows

```bash
# 1. Sign a legal document (use-case-driven)
latticearc keygen --use-case legal-documents -o keys
latticearc sign -i contract.pdf -k keys/hybrid-ml-dsa-65-ed25519.sec.json \
  --public-key keys/hybrid-ml-dsa-65-ed25519.pub.json
latticearc verify -i contract.pdf -s contract.pdf.sig.json

# 2. Encrypt healthcare records
latticearc keygen -a aes256 -o keys
latticearc encrypt --use-case healthcare-records -i records.json -o records.enc.json -k keys/aes256.key.json
latticearc decrypt -i records.enc.json -o records.json -k keys/aes256.key.json

# 3. CI/CD firmware signing
latticearc keygen --use-case firmware-signing -o ci-keys
latticearc hash -a sha-256 -i firmware.bin
latticearc sign -i firmware.bin -k ci-keys/hybrid-ml-dsa-65-ed25519.sec.json \
  --public-key ci-keys/hybrid-ml-dsa-65-ed25519.pub.json
```

## Output Files

| Command | Output | Description |
|---------|--------|-------------|
| `keygen --use-case firmware-signing` | `hybrid-ml-dsa-65-ed25519.{pub,sec}.json` | Signing keypair |
| `keygen -a aes256` | `aes256.key.json` | Symmetric key |
| `sign -i doc.pdf --public-key ...` | `doc.pdf.sig.json` | SignedData envelope |
| `encrypt -i data.txt -o ...` | Specified via `-o` | Encrypted JSON |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (invalid input, wrong key, verification failed) |

## Key Sizes at a Glance

```
ML-DSA-44:  pk=1,312 B  sk=2,560 B  sig=2,420 B   (NIST Cat 2)
ML-DSA-65:  pk=1,952 B  sk=4,032 B  sig=3,309 B   (NIST Cat 3) ← recommended
ML-DSA-87:  pk=2,592 B  sk=4,896 B  sig=4,627 B   (NIST Cat 5)
SLH-DSA:    pk=32 B     sk=64 B     sig=7,856 B   (NIST Cat 1)
FN-DSA-512: pk=897 B    sk=1,281 B  sig=~666 B    (compact)
Ed25519:    pk=32 B     sk=32 B     sig=64 B      (classical)
AES-256:    key=32 B    nonce=12 B  tag=16 B
```
