# LatticeArc CLI User Guide

Post-quantum cryptography from the command line — sign, encrypt, hash, and derive keys
with algorithms designed to resist both classical and quantum computers.

---

## Table of Contents

- [Cheat Sheet](#cheat-sheet)
- [Installation](#installation)
- [Concepts](#concepts)
- [Getting Started](#getting-started)
  - [Your First Signature](#your-first-signature)
  - [Your First Encryption](#your-first-encryption)
- [Choosing an Algorithm](#choosing-an-algorithm)
- [Command Reference](#command-reference)
  - [keygen](#keygen)
  - [sign](#sign)
  - [verify](#verify)
  - [encrypt](#encrypt)
  - [decrypt](#decrypt)
  - [hash](#hash)
  - [kdf](#kdf)
  - [info](#info)
- [File Formats](#file-formats)
- [Real-World Workflows](#real-world-workflows)
- [Security Details](#security-details)
- [Troubleshooting](#troubleshooting)

---

## Cheat Sheet

```
SIGN & VERIFY                          ENCRYPT & DECRYPT
=============                          =================
keygen -a ml-dsa65 -o keys/            keygen -a aes256 -o keys/
sign   -a ml-dsa65 -i FILE -k SEC      encrypt -i FILE -o OUT -k KEY
verify -a ml-dsa65 -i FILE -s SIG -k PUB   decrypt -i OUT -o FILE -k KEY

HASH & KDF                             INFO
==========                             ====
hash -i FILE                           info
hash -i FILE -f base64
kdf -a hkdf -i HEX_IKM -s HEX_SALT
kdf -a pbkdf2 -i "password" -s HEX_SALT
```

---

## Installation

**1. Build:**
```bash
cd apache_repo && cargo build --release -p latticearc-cli
```

**2. Set FIPS library path** (needed for AES-256-GCM and ML-KEM):
```bash
# macOS
export DYLD_LIBRARY_PATH="$(find target/release/build/aws-lc-fips-sys-*/out/build/artifacts \
  -name '*.dylib' -print -quit | xargs dirname)"

# Linux
export LD_LIBRARY_PATH="$(find target/release/build/aws-lc-fips-sys-*/out/build/artifacts \
  -name '*.so' -print -quit | xargs dirname)"
```

**3. Verify:**
```bash
latticearc info
# Look for: "FIPS 140-3 backend: available (aws-lc-rs)"
```

---

## Concepts

### What Does This Tool Do?

LatticeArc CLI performs four core operations on files:

```
  +-----------+     +-----------+     +-----------+     +-----------+
  |   SIGN    |     |  ENCRYPT  |     |   HASH    |     |    KDF    |
  |           |     |           |     |           |     |           |
  | Proves    |     | Hides     |     | Finger-   |     | Derives   |
  | who wrote |     | content   |     | prints    |     | keys from |
  | a file    |     | from      |     | a file    |     | passwords |
  |           |     | others    |     |           |     | or other  |
  +-----------+     +-----------+     +-----------+     | keys      |
                                                        +-----------+
```

### Keys: The Lock & Key Analogy

```
  SYMMETRIC KEY (aes256)          ASYMMETRIC KEYPAIR (ml-dsa65, ed25519, etc.)
  ========================        ============================================

  Same key encrypts               Two keys work together:
  AND decrypts:
                                    Public Key (.pub.json)
  +-------+                         - Share with everyone
  |  KEY  |  <-- one key            - Used to VERIFY signatures
  +-------+      for both           - Like a mailbox address
  encrypt <------> decrypt
                                    Secret Key (.sec.json)
                                    - Keep private! (0600 permissions)
                                    - Used to SIGN files
                                    - Like a mailbox key
```

### How Signing Works

Signing proves a file hasn't been tampered with and came from the key holder:

```
  SIGNING                                    VERIFYING
  =======                                    =========

  document.pdf ----+                         document.pdf ----+
                   |                                          |
                   v                                          v
             +----------+                              +----------+
             |   sign   |                              |  verify  |
             +----------+                              +----------+
                   |                                     |       |
  secret key ----->+                     public key ---->+       |
  (.sec.json)      |                     (.pub.json)             |
                   v                                             v
          document.pdf.sig.json ---------------------> "VALID" or "INVALID"
```

### How Encryption Works

```
  ENCRYPTING                                 DECRYPTING
  ==========                                 ==========

  secret.txt -------+                        encrypted.json ---+
                    |                                          |
                    v                                          v
             +-----------+                              +-----------+
             |  encrypt  |                              |  decrypt  |
             +-----------+                              +-----------+
                    |                                          |
  aes256.key.json ->+                     aes256.key.json ---->+
                    |                                          |
                    v                                          v
          encrypted.json                               secret.txt
          (ciphertext + nonce                          (original file,
           + auth tag)                                  byte-for-byte)
```

---

## Getting Started

### Your First Signature

Let's sign a file so anyone can verify it came from you.

**Step 1 — Generate a signing keypair:**
```bash
latticearc keygen -a ml-dsa65 -o keys/
```
```
Generated ML-DSA-65 signing keypair:
  Public:  keys/ml-dsa-65.pub.json     <-- share this
  Secret:  keys/ml-dsa-65.sec.json     <-- keep this private!
```

**Step 2 — Sign your file:**
```bash
latticearc sign -a ml-dsa65 -i report.pdf -k keys/ml-dsa-65.sec.json
```
```
Signature written to: report.pdf.sig.json
```

**Step 3 — Anyone with your public key can verify:**
```bash
latticearc verify -a ml-dsa65 \
  -i report.pdf \
  -s report.pdf.sig.json \
  -k keys/ml-dsa-65.pub.json
```
```
Signature is VALID.
```

What just happened:
```
  keys/                              You send these two files
  +-- ml-dsa-65.pub.json             to the recipient:
  +-- ml-dsa-65.sec.json
                                       report.pdf
  report.pdf                           report.pdf.sig.json
  report.pdf.sig.json                  ml-dsa-65.pub.json
```

### Your First Encryption

Let's encrypt a file so only someone with the key can read it.

**Step 1 — Generate an encryption key:**
```bash
latticearc keygen -a aes256 -o keys/
```
```
Generated AES-256 symmetric key: keys/aes256.key.json
```

**Step 2 — Encrypt:**
```bash
latticearc encrypt -i secret.txt -o secret.enc.json -k keys/aes256.key.json
```

**Step 3 — Decrypt:**
```bash
latticearc decrypt -i secret.enc.json -o recovered.txt -k keys/aes256.key.json
```

`recovered.txt` is byte-for-byte identical to `secret.txt`.

---

## Choosing an Algorithm

### "Which signing algorithm should I use?"

```
                        Do you need quantum resistance?
                                    |
                     +--------------+---------------+
                     |                              |
                    YES                             NO
                     |                              |
              Need maximum                    Ed25519
              security?                    (fastest, smallest)
                     |
          +----------+----------+
          |                     |
         YES                   NO
          |                     |
     ML-DSA-87             ML-DSA-65
   (NIST Level 5)       (recommended default)
```

#### Signing Algorithms Compared

```
Algorithm        Quantum-Safe   PK Size    Sig Size   Speed
-----------      ----------     --------   --------   --------
Ed25519             No           32 B       64 B      fastest
ML-DSA-44          Yes         1,312 B    2,420 B      fast
ML-DSA-65          Yes         1,952 B    3,309 B      fast     <-- recommended
ML-DSA-87          Yes         2,592 B    4,627 B      fast
SLH-DSA            Yes           32 B     7,856 B      slow
FN-DSA-512         Yes          ~897 B     ~666 B      fast
Hybrid             Yes        ~1,984 B   ~3,373 B      fast
(ML-DSA-65+Ed25519)
```

**Recommendations:**
- **General purpose:** `ml-dsa65` — good balance of security and size
- **Maximum security:** `ml-dsa87` — NIST Level 5 (equivalent to AES-256)
- **Transition period:** `hybrid` — PQ + classical, safe even if one algorithm is broken
- **Classical only:** `ed25519` — smallest and fastest, but not quantum-resistant
- **Conservative/paranoid:** `slh-dsa` — hash-based (different math than lattices), but large signatures

### "Which encryption mode should I use?"

```
                      Do you have a shared secret key?
                                    |
                     +--------------+---------------+
                     |                              |
                    YES                             NO
                     |                              |
              aes256-gcm                       hybrid
         (symmetric, fastest)          (PQ key encapsulation)
                                     (recipient shares public key)
```

| Mode | Flag | Use When... |
|------|------|-------------|
| AES-256-GCM | `-m aes256-gcm` | Both parties have the same secret key |
| Hybrid | `-m hybrid` | You have the recipient's public key (like PGP/GPG) |

---

## Command Reference

### keygen

Generate cryptographic keys.

```
latticearc keygen -a ALGORITHM [-o DIR] [-l LABEL]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-a` | Algorithm (see table below) | *required* |
| `-o` | Output directory | `.` (current dir) |
| `-l` | Human-readable label | none |

**All supported algorithms:**

```
ENCRYPTION KEYS                   SIGNING KEYS
===============                   ============
-a aes256       AES-256           -a ed25519      Ed25519 (classical)
-a ml-kem512    ML-KEM-512        -a ml-dsa44     ML-DSA-44
-a ml-kem768    ML-KEM-768        -a ml-dsa65     ML-DSA-65
-a ml-kem1024   ML-KEM-1024       -a ml-dsa87     ML-DSA-87
-a hybrid       ML-KEM+X25519     -a slh-dsa128s  SLH-DSA-128s
                                  -a fn-dsa512    FN-DSA-512
                                  -a hybrid-sign  ML-DSA-65+Ed25519
```

**Output files created:**

```
latticearc keygen -a ml-dsa65 -o keys/

  keys/
  +-- ml-dsa-65.pub.json     <-- public key  (share freely)
  +-- ml-dsa-65.sec.json     <-- secret key  (0600 permissions, keep private)


latticearc keygen -a aes256 -o keys/

  keys/
  +-- aes256.key.json        <-- symmetric key (0600 permissions, keep private)
```

**Examples:**
```bash
# With a label
latticearc keygen -a aes256 -o keys/ -l "database-encryption-2026"

# All ML-KEM levels
for level in ml-kem512 ml-kem768 ml-kem1024; do
  latticearc keygen -a $level -o keys/$level/
done
```

---

### sign

Sign a file with your secret key.

```
latticearc sign -a ALGORITHM -i FILE -k SECRET_KEY [-o SIGFILE]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-a` | Algorithm | *required* |
| `-i` | File to sign | *required* |
| `-k` | Secret key file (`.sec.json`) | *required* |
| `-o` | Output signature file | `<input>.sig.json` |

```
ALGORITHM VALUES:  ed25519  ml-dsa44  ml-dsa65  ml-dsa87  slh-dsa  fn-dsa  hybrid
```

**How it works:**

```
  Input:   report.pdf + keys/ml-dsa-65.sec.json
                |
                v
  +----------------------------+
  |  latticearc sign           |
  |  -a ml-dsa65               |
  |  -i report.pdf             |
  |  -k keys/ml-dsa-65.sec.json|
  +----------------------------+
                |
                v
  Output:  report.pdf.sig.json
           {
             "algorithm": "ml-dsa-65",
             "signature": "base64..."
           }
```

**Examples:**
```bash
# Default output path (report.pdf -> report.pdf.sig.json)
latticearc sign -a ml-dsa65 -i report.pdf -k keys/ml-dsa-65.sec.json

# Explicit output path
latticearc sign -a ed25519 -i release.tar.gz -o release.sig -k keys/ed25519.sec.json

# Hybrid signature (creates both PQ + classical signatures)
latticearc sign -a hybrid -i firmware.bin -k keys/hybrid-sign.sec.json
```

---

### verify

Check if a signature is valid.

```
latticearc verify -a ALGORITHM -i FILE -s SIGFILE -k PUBLIC_KEY
```

| Flag | Description |
|------|-------------|
| `-a` | Algorithm (must match what was used to sign) |
| `-i` | Original file that was signed |
| `-s` | Signature file (`.sig.json`) |
| `-k` | Public key file (`.pub.json`) |

**Output:**
```
Signature is VALID.      <-- exit code 0 (success)
Signature is INVALID.    <-- exit code 1 (failure)
```

**Example:**
```bash
latticearc verify -a ml-dsa65 \
  -i report.pdf \
  -s report.pdf.sig.json \
  -k keys/ml-dsa-65.pub.json
```

---

### encrypt

Encrypt a file.

```
latticearc encrypt [-m MODE] [-i FILE] [-o FILE] -k KEYFILE
```

| Flag | Description | Default |
|------|-------------|---------|
| `-m` | Mode: `aes256-gcm` or `hybrid` | `aes256-gcm` |
| `-i` | Input file | stdin |
| `-o` | Output file | stdout |
| `-k` | Key file | *required* |

**How AES-256-GCM encryption works:**

```
                         +------------------+
  plaintext.txt -------->|                  |
                         |  AES-256-GCM     |------> encrypted.json
  aes256.key.json ------>|  (random nonce)  |        {
                         +------------------+          "scheme": "...",
                                                       "ciphertext": "...",
                                                       "nonce": "...",
                                                       "tag": "..."
                                                     }
```

**How hybrid encryption works:**

```
                         +------------------+
  plaintext.txt -------->|                  |
                         | 1. ML-KEM-768    |
  hybrid-kem.pub.json -->|    key exchange  |------> encrypted.json
                         | 2. X25519 ECDH   |        (includes ML-KEM
                         | 3. HKDF combine  |         ciphertext +
                         | 4. AES-256-GCM   |         ECDH public key +
                         +------------------+         AES ciphertext)
```

**Examples:**
```bash
# Symmetric
latticearc encrypt -i secret.txt -o secret.enc.json -k keys/aes256.key.json

# Hybrid post-quantum
latticearc encrypt -m hybrid -i secret.txt -o secret.enc.json -k keys/hybrid-kem.pub.json

# Pipe from stdin
echo "secret" | latticearc encrypt -k keys/aes256.key.json -o out.json
```

---

### decrypt

Decrypt a file encrypted by `latticearc encrypt`.

```
latticearc decrypt [-i FILE] [-o FILE] -k KEYFILE
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Encrypted JSON file | stdin |
| `-o` | Output file for plaintext | stdout |
| `-k` | Symmetric key file | *required* |

**Examples:**
```bash
# To file
latticearc decrypt -i secret.enc.json -o secret.txt -k keys/aes256.key.json

# To stdout
latticearc decrypt -i secret.enc.json -k keys/aes256.key.json

# From stdin
cat encrypted.json | latticearc decrypt -k keys/aes256.key.json -o out.bin
```

> **Note:** Hybrid decryption is not available in the CLI (the hybrid secret key is
> ephemeral). Use the `latticearc` Rust library API for hybrid decryption.

---

### hash

Compute a SHA3-256 hash (fingerprint) of a file.

```
latticearc hash [-i FILE] [-f FORMAT]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Input file | stdin |
| `-f` | Output format: `hex` or `base64` | `hex` |

**How it works:**

```
  Any file (any size) -----> SHA3-256 -----> 32-byte fingerprint
                                             (64 hex chars)

  Same input = always the same output
  Change 1 bit = completely different output
```

**Examples:**
```bash
latticearc hash -i document.pdf
# SHA3-256: 3798e7e34c6d51187039ca44860152511f39b63774f5ca5ad0f72e258641314b

latticearc hash -i document.pdf -f base64
# SHA3-256: N5jn40xtURhwOcpEhgFSUR85tjd09cpNoPcuJYZBMUs=

echo -n "hello" | latticearc hash
# SHA3-256: ...

# Well-known empty hash (verifiable against any implementation)
latticearc hash -i /dev/null
# SHA3-256: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

---

### kdf

Derive a cryptographic key from a password or existing key material.

```
latticearc kdf -a ALGORITHM -i INPUT -s SALT [-l LENGTH] [--info INFO] [--iterations N] [-f FORMAT]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-a` | `hkdf` or `pbkdf2` | *required* |
| `-i` | Input: hex key material (HKDF) or password text (PBKDF2) | *required* |
| `-s` | Salt (hex-encoded) | *required* |
| `-l` | Output length in bytes | `32` |
| `--info` | Context string (HKDF only) | `""` |
| `--iterations` | Iteration count (PBKDF2 only) | `600000` |
| `-f` | Output format: `hex` or `base64` | `hex` |

**When to use which:**

```
  HKDF (from existing key material)        PBKDF2 (from a password)
  =================================        ========================

  You already have a strong key            You have a human password
  and need to derive sub-keys:             and need to make a key:

  master_key ---> HKDF ---> enc_key        "p@ssword" --> PBKDF2 --> key
                       +--> mac_key          (600,000 iterations
                       +--> auth_key          make brute-force slow)
```

**HKDF example** (input and salt are hex-encoded):
```bash
latticearc kdf -a hkdf \
  -i 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
  -s 000102030405060708090a0b0c \
  --info "encryption-key" \
  -l 32
```

**PBKDF2 example** (input is plaintext password, salt is hex):
```bash
latticearc kdf -a pbkdf2 \
  -i "my-secure-password" \
  -s 73616c74 \
  -l 32
```

---

### info

Show version, FIPS status, and all supported algorithms.

```bash
latticearc info
```

```
LatticeArc CLI v0.3.3
Library:  latticearc v0.3.3

FIPS 140-3 backend: available (aws-lc-rs)    <-- confirms FIPS is loaded
Self-tests passed:  true                      <-- FIPS power-on self-tests OK

Supported Algorithms:
  Encryption:
    AES-256-GCM, ML-KEM-512/768/1024, Hybrid ML-KEM+X25519
  Signatures:
    ML-DSA-44/65/87, SLH-DSA-SHAKE-128s, FN-DSA-512, Ed25519, Hybrid
  Hashing:
    SHA3-256
  Key Derivation:
    HKDF-SHA256, PBKDF2-HMAC-SHA256
```

---

## File Formats

### Key File (`.pub.json`, `.sec.json`, `.key.json`)

```json
{
  "version": 1,                        // format version
  "algorithm": "ml-dsa-65",            // which algorithm this key is for
  "key_type": "secret",                // "public", "secret", or "symmetric"
  "key": "base64-encoded-bytes...",    // the actual key material
  "created": "2026-03-09T12:00:00Z",  // when the key was generated
  "label": "my-signing-key"           // optional (omitted if not set)
}
```

**Visual anatomy:**
```
  +------------------------------------------+
  | ml-dsa-65.sec.json                       |
  |                                          |
  |  version: 1          format version      |
  |  algorithm: ml-dsa-65   must match -a    |
  |  key_type: secret     determines usage   |
  |  key: "R2l0SHViLi4."  actual key bytes   |
  |  created: 2026-03-09   ISO 8601          |
  |  label: "prod-key"    your description   |
  |                                          |
  |  Permissions: 0600 (owner only)          |
  +------------------------------------------+
```

**File naming:**
```
  keygen -a ALGORITHM -o keys/

  aes256        -->  keys/aes256.key.json
  ed25519       -->  keys/ed25519.pub.json + keys/ed25519.sec.json
  ml-dsa65      -->  keys/ml-dsa-65.pub.json + keys/ml-dsa-65.sec.json
  ml-kem768     -->  keys/ml-kem-768.pub.json + keys/ml-kem-768.sec.json
  hybrid        -->  keys/hybrid-kem.pub.json (public key only)
  hybrid-sign   -->  keys/hybrid-sign.pub.json + keys/hybrid-sign.sec.json
```

### Signature File (`.sig.json`)

**Standard signature:**
```json
{
  "algorithm": "ml-dsa-65",
  "signature": "base64-encoded-signature..."
}
```

**Hybrid signature** (two signatures in one file):
```json
{
  "algorithm": "hybrid-ml-dsa-65-ed25519",
  "ml_dsa_sig": "base64-ml-dsa-65-signature...",
  "ed25519_sig": "base64-ed25519-signature..."
}
```

### Encrypted Output (`.enc.json`)

```json
{
  "scheme": "aes-256-gcm",
  "ciphertext": "base64...",
  "nonce": "base64...",       // 12 bytes, random, unique per encryption
  "tag": "base64..."          // 16-byte authentication tag
}
```

---

## Real-World Workflows

### CI/CD: Sign Release Artifacts

```
  BUILD SERVER                          DEPLOYMENT TARGET
  ============                          =================

  1. Generate keys (once):              4. Verify before installing:

     keygen -a ml-dsa65                    verify -a ml-dsa65
       -o /secure/keys/                      -i release.tar.gz
       -l "release-signing"                  -s release.tar.gz.sig.json
                                             -k ml-dsa-65.pub.json
  2. Build your release
                                        5. If VALID -> install
  3. Sign each artifact:                   If INVALID -> reject!

     for f in build/*.tar.gz; do
       sign -a ml-dsa65
         -i "$f"
         -k /secure/keys/ml-dsa-65.sec.json
     done

     Ship: *.tar.gz + *.sig.json + pub key
```

### Encrypt Configuration Files

```
  SETUP (once)                          AT RUNTIME
  ============                          ==========

  keygen -a aes256 -o /secure/          decrypt
    -l "config-encryption"                -i config.yaml.enc
                                          -o /tmp/config.yaml
  encrypt                                 -k /secure/aes256.key.json
    -i config.yaml
    -o config.yaml.enc                  # App reads /tmp/config.yaml
    -k /secure/aes256.key.json          # then deletes it
                                        rm /tmp/config.yaml
  # Commit config.yaml.enc to git
  # Never commit aes256.key.json!
```

### File Integrity Checking

```
  PUBLISHER                             CONSUMER
  =========                             ========

  hash -i release.tar.gz               hash -i release.tar.gz
  # SHA3-256: abc123...                 # SHA3-256: abc123...
  # Publish the hash                    # Compare with published hash
                                        # Match = file is unmodified
```

```bash
# Publisher
latticearc hash -i release-v1.0.tar.gz > release-v1.0.sha3

# Consumer
EXPECTED=$(awk '{print $2}' release-v1.0.sha3)
ACTUAL=$(latticearc hash -i release-v1.0.tar.gz | awk '{print $2}')
[ "$EXPECTED" = "$ACTUAL" ] && echo "OK" || echo "TAMPERED!"
```

### Hybrid Quantum-Safe Signing

For maximum safety during the PQ transition, use hybrid signing. The signature
is valid even if one of the two algorithms is later found to be broken.

```
  hybrid-sign keypair
  ===================

  +-- hybrid-sign.pub.json     Contains BOTH:
  |     ML-DSA-65 public key   +  Ed25519 public key
  |
  +-- hybrid-sign.sec.json     Contains BOTH:
        ML-DSA-65 secret key   +  Ed25519 secret key


  Signing produces two signatures:
  ================================

  firmware.bin.sig.json
  {
    "algorithm": "hybrid-ml-dsa-65-ed25519",
    "ml_dsa_sig": "...",      <-- post-quantum signature
    "ed25519_sig": "..."      <-- classical signature
  }

  Verification checks BOTH. If either fails, the file is rejected.
```

```bash
latticearc keygen -a hybrid-sign -o keys/
latticearc sign -a hybrid -i firmware.bin -k keys/hybrid-sign.sec.json
latticearc verify -a hybrid -i firmware.bin -s firmware.bin.sig.json -k keys/hybrid-sign.pub.json
```

### Password-Based Key Derivation

```
  "user-password"  +  random salt  -->  PBKDF2  -->  encryption key
                                        (600K iterations)
```

```bash
# Generate a random salt
SALT=$(openssl rand -hex 16)

# Derive a 32-byte AES key from the password
latticearc kdf -a pbkdf2 -i "user-password" -s "$SALT" -l 32

# Store the salt alongside the ciphertext (salt is not secret)
```

---

## Security Details

### What the CLI Does Automatically

```
  +---------------------------+-------------------------------------------+
  | Protection                | How it works                              |
  +---------------------------+-------------------------------------------+
  | Key file permissions      | Secret/symmetric keys get 0600 (Unix)     |
  | Memory zeroization        | Key material wiped when no longer needed  |
  | Fresh nonces              | Random 12-byte nonce per encryption       |
  | Algorithm validation      | Key file algorithm must match -a flag     |
  | Key type enforcement      | Can't sign with public key, etc.          |
  | FIPS self-tests           | Run automatically at startup              |
  | Debug redaction           | Secret keys show [REDACTED] in logs       |
  | Uniform error codes       | All failures return exit 1 (no oracle)    |
  +---------------------------+-------------------------------------------+
```

### Key Sizes (NIST FIPS 203/204/205)

```
  SIGNING KEYS                          ENCRYPTION KEYS
  ============                          ===============

  Algorithm    PK       SK     Sig      Algorithm     PK       SK
  ---------  ------  ------  ------     ---------   ------   ------
  Ed25519      32 B    32 B    64 B     AES-256       n/a      32 B
  ML-DSA-44  1312 B  2560 B  2420 B     ML-KEM-512   800 B   1632 B
  ML-DSA-65  1952 B  4032 B  3309 B     ML-KEM-768  1184 B   2400 B
  ML-DSA-87  2592 B  4896 B  4627 B     ML-KEM-1024 1568 B   3168 B
  SLH-DSA      32 B    64 B  7856 B
  FN-DSA-512 ~897 B ~1281 B  ~666 B
```

### NIST Security Levels

```
  Level 1 (AES-128 equivalent):  ML-KEM-512, SLH-DSA-128s, FN-DSA-512
  Level 2 (AES-128+ equivalent): ML-DSA-44
  Level 3 (AES-192 equivalent):  ML-KEM-768, ML-DSA-65          <-- recommended
  Level 5 (AES-256 equivalent):  ML-KEM-1024, ML-DSA-87
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Any error (wrong key, tampered data, missing file, etc.) |

All errors return exit code 1 — this is intentional. Returning different codes
for "wrong key" vs "tampered data" would let attackers distinguish failure modes.

---

## Troubleshooting

### Quick Diagnosis

```
  Problem                              Solution
  -------                              --------
  "Library initialization failed"      Set DYLD_LIBRARY_PATH / LD_LIBRARY_PATH
  "Key algorithm mismatch"             Check: -a flag must match key's algorithm
  "Expected secret key, got Public"    Use .sec.json for signing, not .pub.json
  "Expected public key, got Secret"    Use .pub.json for verify, not .sec.json
  "Expected symmetric key, got Public" Use aes256.key.json for encrypt/decrypt
  "Hybrid decryption requires..."      Use library API (CLI can't decrypt hybrid)
  SLH-DSA is very slow                 Normal — use release mode, expect ~100ms
  FN-DSA stack overflow                Use --release (debug mode needs too much stack)
```

### "Library initialization failed"

The FIPS shared library isn't found. Fix:

```bash
# macOS
export DYLD_LIBRARY_PATH="$(find target/release/build/aws-lc-fips-sys-*/out/build/artifacts \
  -name '*.dylib' -print -quit | xargs dirname)"

# Verify
latticearc info   # Should show "FIPS 140-3 backend: available"
```

### "Key algorithm mismatch"

The `-a` flag doesn't match the key file's `algorithm` field. Check:

```bash
# See what algorithm the key was generated for
cat keys/my-key.sec.json | python3 -c "import sys,json; print(json.load(sys.stdin)['algorithm'])"
# Output: ed25519

# Then use that same algorithm
latticearc sign -a ed25519 -i file.txt -k keys/my-key.sec.json
```

### Wrong Key Type

```
  OPERATION    NEEDS                   FILE PATTERN
  ---------   -----                   ------------
  sign         Secret key             *.sec.json
  verify       Public key             *.pub.json
  encrypt      Symmetric OR Public    *.key.json  OR  *.pub.json
  decrypt      Symmetric key          *.key.json
```

```bash
# WRONG: signing with public key
latticearc sign -a ed25519 -i file.txt -k keys/ed25519.pub.json
# Error: Expected secret key file for signing, got Public

# RIGHT: signing with secret key
latticearc sign -a ed25519 -i file.txt -k keys/ed25519.sec.json
```

### Performance

```
  Operation          Release Mode    Debug Mode
  ---------          ------------    ----------
  ML-DSA-65 sign     < 1 ms          ~5 ms
  SLH-DSA sign       ~100 ms         ~1000 ms     <-- always use release
  AES-256-GCM        < 1 ms          ~2 ms
  ML-KEM-768 keygen  < 1 ms          ~10 ms
  FN-DSA sign        < 1 ms          STACK OVERFLOW  <-- must use release
```

Always build with `--release`:
```bash
cargo build --release -p latticearc-cli
```
