# LatticeArc CLI — Quick Reference

## Generate Keys

```bash
latticearc keygen -a <algorithm> -o <dir> [-l <label>]
```

| Short Flag | Algorithm | What It Does |
|------------|-----------|--------------|
| `-a ml-dsa65` | ML-DSA-65 | Signing key (recommended) |
| `-a ml-dsa44` | ML-DSA-44 | Signing key (faster) |
| `-a ml-dsa87` | ML-DSA-87 | Signing key (strongest) |
| `-a slh-dsa128s` | SLH-DSA | Signing key (hash-based) |
| `-a fn-dsa512` | FN-DSA-512 | Signing key (compact) |
| `-a ed25519` | Ed25519 | Signing key (classical) |
| `-a hybrid-sign` | ML-DSA-65+Ed25519 | Dual signing key |
| `-a aes256` | AES-256 | Symmetric encryption key |
| `-a ml-kem768` | ML-KEM-768 | Key exchange (default) |
| `-a ml-kem512` | ML-KEM-512 | Key exchange (fast) |
| `-a ml-kem1024` | ML-KEM-1024 | Key exchange (strongest) |
| `-a hybrid` | ML-KEM+X25519 | Hybrid encryption |

## Sign & Verify

```bash
# Sign
latticearc sign -a <algorithm> -i <file> -k <secret.key.json> [-o <sig.json>]

# Verify (algorithm auto-detected from signature file)
latticearc verify -i <file> -s <sig.json> -k <public.key.json>
```

Sign algorithms: `ml-dsa65`, `ml-dsa44`, `ml-dsa87`, `slh-dsa`, `fn-dsa`, `ed25519`, `hybrid`

## Encrypt & Decrypt

```bash
# Encrypt
latticearc encrypt -m aes256-gcm -i <file> -o <enc.json> -k <key.json>

# Decrypt
latticearc decrypt -i <enc.json> -o <file> -k <key.json>
```

Modes: `aes256-gcm`, `hybrid`

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
# 1. Sign a release artifact
latticearc keygen -a ml-dsa65 -o keys
latticearc sign -a ml-dsa65 -i app.tar.gz -k keys/ml-dsa-65.sec.json
latticearc verify -i app.tar.gz -s app.tar.gz.sig.json -k keys/ml-dsa-65.pub.json

# 2. Encrypt a config file
latticearc keygen -a aes256 -o keys
latticearc encrypt -m aes256-gcm -i secrets.json -o secrets.enc.json -k keys/aes256.key.json
latticearc decrypt -i secrets.enc.json -o secrets.json -k keys/aes256.key.json

# 3. Hash + sign (verify integrity chain)
latticearc hash -a sha-256 -i firmware.bin
latticearc sign -a ml-dsa87 -i firmware.bin -k keys/ml-dsa-87.sec.json
```

## Output Files

| Input | Output | Description |
|-------|--------|-------------|
| `keygen -a ml-dsa65` | `ml-dsa-65.pub.json`, `ml-dsa-65.sec.json` | Key pair |
| `keygen -a aes256` | `aes256.key.json` | Symmetric key |
| `sign -i doc.pdf` | `doc.pdf.sig.json` | Signature |
| `encrypt -i data.txt` | Specified via `-o` | Encrypted JSON |

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
