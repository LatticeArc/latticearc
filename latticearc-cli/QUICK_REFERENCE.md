# LatticeArc CLI — Quick Reference

## Generate Keys

**Recommended** — express intent, library selects the algorithm:

```bash
latticearc-cli keygen --use-case <USE_CASE> [-o <dir>] [-l <label>]
```

**Expert** — specify algorithm directly:

```bash
latticearc-cli keygen -a <algorithm> -o <dir> [-l <label>]
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
latticearc-cli sign -i <file> -k <secret.json> --public-key <public.json>

# Sign (expert — explicit algorithm)
latticearc-cli sign -a <algorithm> -i <file> -k <secret.json>

# Verify (algorithm auto-detected, PK embedded in SignedData)
latticearc-cli verify -i <file> -s <sig.json>

# Verify (legacy format — requires --key)
latticearc-cli verify -i <file> -s <sig.json> -k <public.json>
```

## Encrypt & Decrypt

```bash
# Encrypt (recommended — use-case-driven)
latticearc-cli encrypt --use-case <USE_CASE> -i <file> -o <enc.json> -k <key.json>

# Encrypt (expert — explicit mode)
latticearc-cli encrypt -m aes256-gcm -i <file> -o <enc.json> -k <key.json>

# Decrypt
latticearc-cli decrypt -i <enc.json> -o <file> -k <key.json>
```

Modes: `aes256-gcm`, `chacha20-poly1305`, `hybrid`, `pq-only`

`pq-only` is the only CNSA 2.0-compliant mode — pure ML-KEM-768 + AES-256-GCM with no classical sidecar. Use it when CNSA 2.0 (NSA Commercial National Security Algorithm Suite 2.0) compliance is required; `hybrid` retains an X25519 component as transitional defence-in-depth per NIST SP 800-227.

## Hash

```bash
latticearc-cli hash -a <algorithm> -i <file> [-f <hex|base64>]
```

Algorithms: `sha3-256` (default), `sha-256`, `sha-512`, `blake2b`

## Key Derivation

```bash
# From key material (HKDF)
latticearc-cli kdf -a hkdf -i <hex_key> -s <hex_salt> [-l <bytes>] [--info <text>]

# From password (PBKDF2)
latticearc-cli kdf -a pbkdf2 -i <password> -s <hex_salt> [-l <bytes>] [--iterations <n>]
```

## Info

```bash
latticearc-cli info       # Show version, FIPS status, supported algorithms
latticearc-cli --help     # Show all commands
latticearc-cli <cmd> -h   # Show help for a specific command
```

## Common Workflows

```bash
# 1. Sign a legal document (use-case-driven)
# `legal-documents` use case selects ML-DSA-87 (NIST Level 5 / Maximum)
# per the policy table — the keygen output is ml-dsa-87, not 65.
latticearc-cli keygen --use-case legal-documents -o keys
latticearc-cli sign -i contract.pdf -k keys/hybrid-ml-dsa-87-ed25519.sec.json \
  --public-key keys/hybrid-ml-dsa-87-ed25519.pub.json
latticearc-cli verify -i contract.pdf -s contract.pdf.sig.json

# 2. Encrypt healthcare records
latticearc-cli keygen -a aes256 -o keys
latticearc-cli encrypt --use-case healthcare-records -i records.json -o records.enc.json -k keys/aes256.key.json
latticearc-cli decrypt -i records.enc.json -o records.json -k keys/aes256.key.json

# 3. CI/CD firmware signing
latticearc-cli keygen --use-case firmware-signing -o ci-keys
latticearc-cli hash -a sha-256 -i firmware.bin
latticearc-cli sign -i firmware.bin -k ci-keys/hybrid-ml-dsa-65-ed25519.sec.json \
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

`latticearc-cli verify` follows the openssl/gpg/ssh convention so scripts
can distinguish forgery from operational error:

| Code | Meaning (verify)                                              |
|------|---------------------------------------------------------------|
| `0`  | Signature is **VALID**                                        |
| `1`  | Signature is **INVALID** (forgery / tampering)                |
| `≥2` | Operational error (missing file, wrong key file, bad arg, …)  |

All other commands use:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (invalid input, wrong key, runtime failure) |
| `2` | Bad command-line arguments (clap default) |

## Stdin / env-var input (round-7)

Several commands accept input from stdin or environment to avoid
exposing secrets in `ps` / shell history:

| Command | Stdin path | Env var |
|---------|-----------|---------|
| `kdf` (PBKDF2 password) | `--input-stdin` | `LATTICEARC_KDF_INPUT` |
| `sign` / `verify` (data) | omit `--input` | (not applicable) |
| `encrypt` / `decrypt` / `hash` (data) | omit `--input` | (not applicable) |
| `keygen` (passphrase) | (interactive prompt) | `LATTICEARC_PASSPHRASE` |

For env-var passphrases / inputs: `unset` the variable immediately
after the invocation. The variable is visible to same-UID processes
via `/proc/<pid>/environ` for the lifetime of this process — see
SECURITY.md "Defense in Depth" §7 for the trade-off.

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
