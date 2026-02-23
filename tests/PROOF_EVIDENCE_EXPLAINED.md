# Hybrid Cryptography Proof Evidence Suite — Complete Explanation

**Test file:** `tests/tests/hybrid_proof_evidence.rs`
**Total tests:** 52 functions | **Total proof lines:** 89
**Run command:**
```bash
cargo test --test hybrid_proof_evidence --all-features --release -- --nocapture
```
**Extract proofs:**
```bash
grep "\[PROOF\]" output.txt | sed 's/\[PROOF\] //' > proof_evidence.jsonl
```

---

## How to Read This Document

Each section below follows this structure:
1. **What the test does** — the real cryptographic operation performed
2. **Real-world scenario** — the deployment situation this models
3. **Proof fields explained** — what each JSON field means and why it matters
4. **What PASS proves** — the concrete guarantee established

Every `[PROOF]` line is emitted only AFTER the operation succeeds and all assertions pass. A proof line is not a log message — it is a structured evidence record produced by live cryptographic execution.

---

## Section 1: UseCase to Scheme Selection (22 proof lines)

### What This Tests

When a developer configures `CryptoConfig::new().use_case(UseCase::SecureMessaging)`, the system must automatically select the correct hybrid encryption scheme. The developer never names an algorithm — the policy engine maps the business context to the right security level.

Each of the 22 use cases goes through the full pipeline:
1. Generate a fresh ML-KEM + X25519 keypair at the level dictated by the use case
2. Encrypt a 43-byte message with **no explicit scheme** — only the use case tag
3. Assert the system chose the expected scheme
4. Decrypt and verify the original bytes come back

### Real-World Scenario

A hospital records system calls `encrypt(patient_data, key, config.use_case(UseCase::HealthcareRecords))`. The developer never decides "use ML-KEM-1024" — the policy engine makes that decision based on the regulatory and sensitivity profile of healthcare data. This test proves the policy engine gets it right for every use case, and that the full encrypt/decrypt roundtrip works once the scheme is selected.

This models the real deployment pattern: application developers describe WHAT they're protecting (email, IoT telemetry, government documents), and the cryptographic library decides HOW (which ML-KEM parameter set, which symmetric cipher).

### Proof Fields Explained

```json
{
  "section": 1,
  "test": "usecase_scheme_HealthcareRecords",
  "use_case": "HealthcareRecords",
  "expected_scheme": "hybrid-ml-kem-1024-aes-256-gcm",
  "actual_scheme": "hybrid-ml-kem-1024-aes-256-gcm",
  "ml_kem_ct_bytes": 1568,
  "ecdh_pk_bytes": 32,
  "nonce_bytes": 12,
  "tag_bytes": 16,
  "plaintext_len": 43,
  "ciphertext_len": 43,
  "roundtrip": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `use_case` | The business context tag passed to `CryptoConfig` | Identifies which real-world scenario is being tested |
| `expected_scheme` | The scheme the policy engine SHOULD select | Defined by the security policy — healthcare requires ML-KEM-1024 |
| `actual_scheme` | The scheme the policy engine DID select | Must match `expected_scheme` or the test fails |
| `ml_kem_ct_bytes` | Size of the ML-KEM ciphertext in the output (768/1088/1568) | Proves the correct ML-KEM parameter set was used. These are NIST FIPS 203 spec values — 768 for ML-KEM-512, 1088 for ML-KEM-768, 1568 for ML-KEM-1024 |
| `ecdh_pk_bytes` | Size of the X25519 ephemeral public key (always 32) | Proves the classical ECDH component is present — the "hybrid" in hybrid encryption |
| `nonce_bytes` | AES-256-GCM nonce size (always 12) | 96-bit nonce per NIST SP 800-38D. A wrong nonce size would mean the AEAD is misconfigured |
| `tag_bytes` | AES-256-GCM authentication tag size (always 16) | 128-bit tag provides authenticity. If this were shorter, ciphertext forgery would be easier |
| `plaintext_len` | Bytes of input data (43) | Shows the test used real data, not a trivial empty input |
| `ciphertext_len` | Bytes of AES-GCM ciphertext output (43) | AES-GCM in CTR mode produces ciphertext equal in length to plaintext (stream cipher property). The tag is stored separately. This confirms no padding or data loss |
| `roundtrip` | Whether decrypt(encrypt(data)) == data | The core correctness proof — what went in came back out byte-for-byte |
| `status` | Overall PASS/FAIL | Only printed as PASS if all assertions passed |

### Use Case Groupings

The 22 use cases map to three ML-KEM levels:

**ML-KEM-512 (CT=768 bytes) — Standard security:**
- `IoTDevice` — Constrained devices where bandwidth/compute is limited

**ML-KEM-768 (CT=1088 bytes) — High security (majority):**
- `SecureMessaging`, `VpnTunnel`, `ApiSecurity`, `DatabaseEncryption`, `ConfigSecrets`, `SessionToken`, `AuditLog`, `Authentication`, `DigitalCertificate`, `FinancialTransactions`, `LegalDocuments`, `BlockchainTransaction`, `FirmwareSigning`

**ML-KEM-1024 (CT=1568 bytes) — Maximum security:**
- `EmailEncryption`, `FileStorage`, `CloudStorage`, `BackupArchive`, `KeyExchange`, `HealthcareRecords`, `GovernmentClassified`, `PaymentCard`

This grouping reflects real-world risk: data at rest (files, backups, cloud) and regulated data (healthcare, government, payment) get the strongest protection. Transient data (sessions, API calls) gets high-but-efficient protection. Constrained environments (IoT) get the lightest viable level.

---

## Section 2: SecurityLevel to Scheme Selection (4 proof lines)

### What This Tests

Instead of specifying a use case, a developer can set a `SecurityLevel` directly: `CryptoConfig::new().security_level(SecurityLevel::High)`. This tests that each of the four security levels maps to the correct hybrid scheme.

### Real-World Scenario

An enterprise platform offers a security dial: Standard, High, Maximum, Quantum. An administrator sets the organization-wide default to "High" via a config file. Every encryption operation across every service then uses ML-KEM-768. This test proves that dial works correctly at every setting.

### Proof Fields Explained

```json
{
  "section": 2,
  "test": "security_level_Quantum",
  "security_level": "Quantum",
  "expected_scheme": "hybrid-ml-kem-1024-aes-256-gcm",
  "actual_scheme": "hybrid-ml-kem-1024-aes-256-gcm",
  "ml_kem_ct_bytes": 1568,
  "roundtrip": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `security_level` | The level enum variant (Standard/High/Maximum/Quantum) | The only input — everything else is derived |
| `expected_scheme` / `actual_scheme` | Same as Section 1 | Proves the mapping is correct |
| `ml_kem_ct_bytes` | ML-KEM ciphertext size | Physical proof the right parameter set was used |
| `roundtrip` | Encrypt then decrypt succeeded | The scheme selection isn't just labeling — the crypto actually works |

### Level-to-Scheme Mapping

| SecurityLevel | ML-KEM Variant | CT Size | Rationale |
|---------------|---------------|---------|-----------|
| Standard | ML-KEM-512 | 768 | NIST Security Level 1 — equivalent to AES-128 |
| High | ML-KEM-768 | 1088 | NIST Security Level 3 — equivalent to AES-192 |
| Maximum | ML-KEM-1024 | 1568 | NIST Security Level 5 — equivalent to AES-256 |
| Quantum | ML-KEM-1024 | 1568 | Same as Maximum — strongest available for quantum threat model |

---

## Section 3: ML-KEM NIST FIPS 203 Parameter Verification (3 proof lines)

### What This Tests

NIST published exact byte sizes for ML-KEM public keys, ciphertexts, and shared secrets in FIPS 203, Table 2. This test verifies our implementation produces keys and ciphertexts that match those sizes EXACTLY — both from compile-time constants and from live key generation/encryption.

### Real-World Scenario

When a security auditor reviews a cryptographic library for FIPS compliance, they check that the algorithm output sizes match the standard. If ML-KEM-768 produced an 1100-byte ciphertext instead of 1088, it would indicate a non-conformant implementation. This test is the programmatic version of that audit check.

### Proof Fields Explained

```json
{
  "section": 3,
  "test": "nist_params_ML-KEM-768",
  "level": "ML-KEM-768",
  "pk_bytes": 1184,
  "expected_pk": 1184,
  "ct_bytes": 1088,
  "expected_ct": 1088,
  "ss_bytes": 32,
  "expected_ss": 32,
  "live_pk_bytes": 1184,
  "live_ct_bytes": 1088,
  "all_match": true,
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `level` | ML-KEM parameter set name | Identifies which row of FIPS 203 Table 2 we're checking |
| `pk_bytes` / `expected_pk` | Compile-time constant for public key size vs FIPS 203 spec | The library's constant must match the standard exactly |
| `ct_bytes` / `expected_ct` | Compile-time constant for ciphertext size vs FIPS 203 spec | Ciphertext size determines bandwidth overhead — must be exact |
| `ss_bytes` / `expected_ss` | Shared secret size (always 32 bytes / 256 bits) | The KDF input — must be 32 bytes for all ML-KEM variants |
| `live_pk_bytes` | Actual public key size from `generate_hybrid_keypair_with_level()` | The live-generated key must match the spec, not just the constant |
| `live_ct_bytes` | Actual ciphertext size from `encrypt()` | The live-produced ciphertext must match — this catches serialization bugs |
| `all_match` | Every size matches its expected value | Aggregate pass/fail for the spec check |

### FIPS 203 Table 2 Reference

| Parameter Set | Public Key | Ciphertext | Shared Secret |
|--------------|-----------|------------|---------------|
| ML-KEM-512 | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1,184 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | 1,568 bytes | 1,568 bytes | 32 bytes |

---

## Section 4: Variable-Size Encryption Roundtrip (5 proof lines)

### What This Tests

Encryption must work correctly for any input size — from zero bytes to megabytes. This section encrypts payloads of 0B, 1B, 1KB, 100KB, and 1MB, then decrypts each and verifies byte-for-byte equality.

### Real-World Scenario

Real applications encrypt wildly different data sizes: a 1-byte boolean flag in a config, a 100KB API response payload, a 1MB document. Edge cases like empty payloads occur when encrypting optional fields that happen to be null. This test proves the encryption pipeline handles all these without truncation, padding errors, or buffer overflows.

### Proof Fields Explained

```json
{
  "section": 4,
  "test": "variable_size_1MB",
  "plaintext_len": 1048576,
  "ciphertext_len": 1048576,
  "ml_kem_ct_bytes": 1088,
  "ecdh_pk_bytes": 32,
  "nonce_bytes": 12,
  "tag_bytes": 16,
  "scheme": "hybrid-ml-kem-768-aes-256-gcm",
  "roundtrip": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `plaintext_len` | Input data size in bytes | The variable under test — ranges from 0 to 1,048,576 |
| `ciphertext_len` | Output ciphertext size | Must equal `plaintext_len` because AES-GCM is a stream cipher (CTR mode). Inequality would indicate corruption or unexpected padding |
| `ml_kem_ct_bytes` | ML-KEM ciphertext size (constant 1088 for ML-KEM-768) | The KEM overhead is constant regardless of plaintext size — this is a key property of hybrid encryption |
| `ecdh_pk_bytes` | X25519 ephemeral public key (constant 32) | Classical KEM component is also constant-size |
| `nonce_bytes` | 12-byte AES-GCM nonce | Constant regardless of data size |
| `tag_bytes` | 16-byte authentication tag | Constant regardless of data size |
| `scheme` | The hybrid scheme used | Confirms the same scheme handles all sizes |
| `roundtrip` | decrypt(encrypt(data)) == data | The essential proof that no bytes were lost, added, or corrupted |

### Key Insight

The proof shows that the **overhead is constant**: regardless of whether you encrypt 1 byte or 1MB, the KEM ciphertext (1088), ephemeral public key (32), nonce (12), and tag (16) are always the same size. Only the symmetric ciphertext scales with input. Total overhead = 1088 + 32 + 12 + 16 = 1,148 bytes for any message at ML-KEM-768.

---

## Section 5: Post-Quantum Signature Algorithm Roundtrip (6 proof lines)

### What This Tests

For each signature algorithm supported by LatticeArc, the test:
1. Generates a fresh signing keypair
2. Signs a message
3. Verifies the signature with the public key
4. Reports the key and signature sizes from live execution

This covers three NIST standards plus a hybrid scheme:
- **ML-DSA** (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (FIPS 205): SLH-DSA-SHAKE-128s
- **FN-DSA** (FIPS 206): FN-DSA-512
- **Hybrid**: ML-DSA-65 + Ed25519

### Real-World Scenario

A firmware update server signs each firmware image before distribution. Devices verify the signature before installing. If the signature is invalid or was produced with a different key, the device rejects the update. This test proves that for every algorithm, the sign-then-verify pipeline works: a signature produced by key A verifies with key A's public counterpart.

The hybrid signature (ML-DSA-65 + Ed25519) models the NIST-recommended transition approach: sign with BOTH a post-quantum algorithm and a classical one, so the signature remains valid even if one algorithm is broken.

### Proof Fields — Pure PQ Signatures

```json
{
  "section": 5,
  "test": "sig_ml_dsa_65",
  "algorithm": "ML-DSA-65",
  "standard": "FIPS 204",
  "pk_bytes": 1952,
  "signature_bytes": 3309,
  "message_len": 24,
  "verify": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `algorithm` | The specific signature algorithm | Identifies the NIST parameter set |
| `standard` | The FIPS standard this algorithm implements | Traceability to the specification |
| `pk_bytes` | Public key size in bytes | PQ signatures have much larger keys than classical (Ed25519 is 32 bytes; ML-DSA-65 is 1,952 bytes). This proves the correct parameter set was used |
| `signature_bytes` | Signature size in bytes | Similarly verifiable against the standard's expected output size |
| `message_len` | Input message size | Shows the test used a real message, not empty |
| `verify` | Whether `verify(message, signature, public_key)` returned true | The core proof — the signature is valid |

### Proof Fields — Hybrid Signature

```json
{
  "section": 5,
  "test": "sig_hybrid_ml_dsa_65_ed25519",
  "algorithm": "Hybrid ML-DSA-65+Ed25519",
  "standard": "FIPS 204 + EdDSA",
  "ml_dsa_pk_bytes": 1952,
  "ed25519_pk_bytes": 32,
  "total_pk_bytes": 1984,
  "ml_dsa_sig_bytes": 3309,
  "ed25519_sig_bytes": 64,
  "total_sig_bytes": 3373,
  "message_len": 39,
  "verify": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `ml_dsa_pk_bytes` / `ed25519_pk_bytes` | Individual component key sizes | Shows both algorithms contributed their expected key material |
| `total_pk_bytes` | Sum of both public keys (1952 + 32 = 1984) | The hybrid public key is the concatenation |
| `ml_dsa_sig_bytes` / `ed25519_sig_bytes` | Individual signature sizes | Both algorithms must produce their full signatures |
| `total_sig_bytes` | Combined signature size (3309 + 64 = 3373) | The hybrid signature contains BOTH signatures — verification checks both |
| `verify` | Hybrid verify returned true | Both the PQ and classical signatures are valid against their respective keys |

### Algorithm Size Reference

| Algorithm | Standard | PK (bytes) | Signature (bytes) | Security Level |
|-----------|----------|-----------|-------------------|----------------|
| ML-DSA-44 | FIPS 204 | 1,312 | 2,420 | NIST Level 2 |
| ML-DSA-65 | FIPS 204 | 1,952 | 3,309 | NIST Level 3 |
| ML-DSA-87 | FIPS 204 | 2,592 | 4,627 | NIST Level 5 |
| SLH-DSA-SHAKE-128s | FIPS 205 | 32 | 7,856 | NIST Level 1 |
| FN-DSA-512 | FIPS 206 | 897 | ~666 | NIST Level 1 |
| Hybrid (ML-DSA-65+Ed25519) | FIPS 204 + EdDSA | 1,984 | 3,373 | Level 3 + Classical |

---

## Section 6: Serialization Preserves Scheme Metadata (3 proof lines)

### What This Tests

After encrypting data, the `EncryptedOutput` struct is serialized to JSON (simulating writing to disk or transmitting over a network), then deserialized back. The test verifies that:
1. The `scheme` field survives serialization (the recipient knows which algorithm was used)
2. The ML-KEM ciphertext bytes are identical after round-tripping through JSON
3. The ECDH ephemeral public key bytes are identical
4. Decryption still works from the deserialized output

### Real-World Scenario

A document management system encrypts a file, serializes the `EncryptedOutput` to JSON, and stores it in a database. Days later, a different service reads that JSON, deserializes it, and decrypts. If serialization corrupted any field — the scheme tag, the KEM ciphertext, the nonce, the tag — decryption would fail silently or produce garbage. This test proves the full serialize-then-deserialize-then-decrypt pipeline preserves every byte.

### Proof Fields Explained

```json
{
  "section": 6,
  "test": "serialization_MlKem768",
  "level": "MlKem768",
  "original_scheme": "hybrid-ml-kem-768-aes-256-gcm",
  "restored_scheme": "hybrid-ml-kem-768-aes-256-gcm",
  "json_bytes": 1751,
  "ml_kem_ct_preserved": true,
  "ecdh_pk_preserved": true,
  "decrypt_after_deserialize": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `level` | The ML-KEM security level tested | One test per level (512, 768, 1024) |
| `original_scheme` | Scheme tag on the `EncryptedOutput` before serialization | The ground truth |
| `restored_scheme` | Scheme tag after `deserialize_encrypted_output()` | Must match exactly — if this is wrong, the decryptor would use the wrong algorithm |
| `json_bytes` | Size of the serialized JSON (1323/1751/2392) | Grows with ML-KEM level because the KEM ciphertext is larger. Shows the serialization is compact and scales predictably |
| `ml_kem_ct_preserved` | ML-KEM ciphertext bytes are identical before/after | A single flipped bit in the KEM CT would cause decapsulation failure |
| `ecdh_pk_preserved` | ECDH ephemeral public key bytes are identical | Same — the classical DH component must survive serialization |
| `decrypt_after_deserialize` | Decryption of the deserialized output succeeded | The ultimate proof — the restored struct is functionally identical to the original |

---

## Section 7: Negative Tests — Wrong Key (4 proof lines)

### What This Tests

These tests verify that decryption FAILS when the wrong key is used:
1. **Wrong decrypt key**: Encrypt with keypair A, decrypt with keypair B
2. **ML-KEM-512 key vs ML-KEM-768 ciphertext**: Key size mismatch
3. **ML-KEM-768 key vs ML-KEM-1024 ciphertext**: Key size mismatch
4. **Wrong signature verify key**: Sign with key B, verify with key A

### Real-World Scenario

An attacker intercepts a ciphertext and tries to decrypt it with their own key. Or a misconfigured service accidentally uses the wrong key from a key store. In both cases, decryption MUST fail — not return garbage data, not silently succeed with wrong plaintext. The system must reject the operation with a clear error.

For signatures: if someone forges a firmware update and signs it with their own key, verification against the legitimate vendor's public key must fail.

### Proof Fields Explained

```json
{
  "section": 7,
  "test": "wrong_decrypt_key",
  "expected_error": "decryption failure",
  "actual_error_contains": "Decryption failed: Hybrid decryption failed: Decryption error: AES-GCM decryptio",
  "negative": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `expected_error` | The category of error we expect | Documents the test intent |
| `actual_error_contains` | The first 80 characters of the actual error message | Proves the system produced a specific error, not a generic failure. The AES-GCM decryption error confirms the derived symmetric key was wrong (because the KEM decapsulation produced a different shared secret) |
| `negative` | "PASS" means the operation correctly failed | A negative test passes when the operation fails as expected |

### Why the Error Says "AES-GCM"

In hybrid encryption, the ML-KEM and ECDH shared secrets are combined via HKDF to derive the AES-256-GCM key. When you use the wrong private key, KEM decapsulation produces a different shared secret, HKDF derives a different symmetric key, and AES-GCM decryption fails because the authentication tag doesn't match. The error propagates up as an AES-GCM error — which is correct and expected.

For cross-level mismatches (ML-KEM-512 key vs ML-KEM-768 ciphertext), the system catches this BEFORE attempting decryption and returns a "Configuration error: Scheme mismatch" — the key literally cannot be used with the wrong scheme.

---

## Section 8: Negative Tests — Corrupted Ciphertext (5 proof lines)

### What This Tests

After encrypting data, ONE byte is flipped (XOR 0xFF) in each of five distinct fields of the `EncryptedOutput`:
1. **ML-KEM ciphertext** — the PQ key encapsulation output
2. **ECDH ephemeral public key** — the classical DH component
3. **Symmetric ciphertext** — the AES-GCM encrypted data
4. **Nonce** — the 12-byte AES-GCM IV
5. **Authentication tag** — the 16-byte MAC

Each corruption must cause decryption to fail.

### Real-World Scenario

Data corruption can occur in storage (disk bit rot), in transit (network errors), or from deliberate tampering (active attacker modifying ciphertext). AES-GCM is an authenticated cipher — it detects ANY modification to the ciphertext, nonce, or tag. The ML-KEM and ECDH components are also integrity-critical: corrupting either one means the wrong symmetric key is derived, which the authentication tag then catches.

This test proves that the system has NO silent failure mode for corruption. Every single byte matters.

### Proof Fields Explained

```json
{
  "section": 8,
  "test": "corrupted_ml_kem_ciphertext",
  "corrupted_field": "ml_kem_ciphertext",
  "expected_error": "decryption failure",
  "actual_error_contains": "Decryption failed: Hybrid decryption failed: Decryption error: AES-GCM decryptio",
  "negative": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `corrupted_field` | Which field had one byte flipped | Identifies the attack surface being tested |
| `expected_error` | "decryption failure" | Any corruption must be detected |
| `actual_error_contains` | The real error message | All five corruptions produce AES-GCM errors because: (1) corrupting KEM/ECDH derives wrong symmetric key, (2) corrupting ciphertext/nonce/tag fails the AEAD authentication check |
| `negative` | "PASS" means corruption was detected | The system correctly refused to return corrupted data |

### Why All Errors Look the Same

This is a SECURITY FEATURE. The error message does NOT reveal WHICH field was corrupted. An attacker who corrupts different fields and observes different error messages could use that as an oracle to learn about the plaintext. By always reporting "AES-GCM decryption failed," the system prevents this information leakage. This follows OWASP guidance on not distinguishing between different crypto failure modes.

---

## Section 9: Negative Tests — Wrong AAD (2 proof lines)

### What This Tests

AES-GCM supports Additional Authenticated Data (AAD) — data that is authenticated but not encrypted. If the AAD at decryption time doesn't match the AAD at encryption time, decryption fails.

Two cases:
1. **Mismatched AAD**: Encrypt with "context-a", decrypt with "context-b"
2. **Missing AAD**: Encrypt with "required-context", decrypt with empty string

### Real-World Scenario

AAD binds ciphertext to a specific context. A healthcare system encrypts patient records with AAD = `"patient:12345"`. If someone copies that ciphertext and tries to decrypt it with AAD = `"patient:67890"` (e.g., trying to attach one patient's data to another's record), decryption fails. This prevents context-swapping attacks where ciphertext is valid but is being used in the wrong place.

The "missing AAD" test models a system where an older version of the software doesn't know about AAD and tries to decrypt without it — this must also fail.

### Proof Fields Explained

```json
{
  "section": 9,
  "test": "wrong_aad",
  "encrypt_aad": "context-a",
  "decrypt_aad": "context-b",
  "expected_error": "decryption failure",
  "actual_error_contains": "Decryption failed: Unspecified",
  "negative": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `encrypt_aad` | The AAD string used during encryption | The ground truth context |
| `decrypt_aad` | The AAD string used during decryption attempt | Must match `encrypt_aad` exactly or decryption fails |
| `expected_error` | "decryption failure" | AAD mismatch must be indistinguishable from other failures |
| `actual_error_contains` | "Decryption failed: Unspecified" | Generic error — does NOT reveal that the AAD was the problem (this is intentional for security) |

---

## Section 10: Negative Tests — Cross-Level Key/Scheme Mismatch (3 proof lines)

### What This Tests

What happens when a key generated for one ML-KEM level is used with a scheme that expects a different level? For example:
1. ML-KEM-512 key + ML-KEM-768 scheme
2. ML-KEM-768 key + ML-KEM-1024 scheme
3. ML-KEM-1024 key + ML-KEM-512 scheme

All three must fail at encryption time — the system must not silently use the wrong key size.

### Real-World Scenario

In a key management system, keys are tagged with their security level. A misconfiguration or bug could cause a Level-1 key (ML-KEM-512) to be passed to a Level-3 encryption operation (ML-KEM-768). Rather than silently producing an invalid ciphertext that can never be decrypted, the system must reject this immediately with a clear error.

### Proof Fields Explained

```json
{
  "section": 10,
  "test": "cross_level_512_key_768_scheme",
  "key_level": "MlKem512",
  "expected_error": "key level mismatch",
  "actual_error_contains": "Configuration error: Configuration error: Scheme 'hybrid-ml-kem-768-aes-256-gcm'",
  "negative": "PASS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `key_level` | The ML-KEM level the key was generated for | The "actual" level of the key |
| `expected_error` | "key level mismatch" | The system should detect the incompatibility |
| `actual_error_contains` | "Configuration error: Scheme '...'" | The error names the scheme that conflicts with the key — helpful for debugging in production |

### Why This Is Caught at Encryption Time

The policy engine validates that the key's ML-KEM level matches the scheme's expected level BEFORE attempting encryption. This is a fail-fast design: rather than producing a ciphertext that silently fails at decryption (possibly much later, in a different service), the error is raised immediately when the misconfiguration is detected.

---

## Section 11: TLS Policy Engine and Live Handshake Proof (23 proof lines)

### 11a: TLS UseCase to Mode Selection (10 proof lines)

#### What This Tests

The TLS policy engine maps 10 deployment use cases to one of three TLS modes: Classic (X25519 only), Hybrid (X25519 + ML-KEM-768), or PQ-only. Each use case is tested to confirm the policy engine selects the correct mode AND that the `TlsConfig` builder correctly wires the mode through.

#### Real-World Scenario

A DevOps engineer configures TLS for different services: `TlsConfig::new().use_case(TlsUseCase::Government)` automatically selects PQ-only mode (maximum quantum resistance). `TlsConfig::new().use_case(TlsUseCase::IoT)` selects Classic mode (IoT devices may not support PQ key exchange). The engineer never manually selects cipher suites.

#### Proof Fields

```json
{
  "section": 11,
  "test": "tls_usecase_Government",
  "tls_use_case": "Government",
  "expected_mode": "Pq",
  "actual_mode": "Pq",
  "config_wired": true,
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `tls_use_case` | The deployment context | Determines the policy decision |
| `expected_mode` / `actual_mode` | The TLS mode the policy engine should/did select | Must match |
| `config_wired` | The `TlsConfig` builder correctly propagated the mode | Proves the builder pattern doesn't silently drop the use case |

#### Mode Assignments

| Use Case | Mode | Rationale |
|----------|------|-----------|
| WebServer | Hybrid | Public-facing servers need PQ protection but must stay compatible with classical clients |
| InternalService | Hybrid | Internal traffic should use PQ but doesn't need PQ-only strictness |
| ApiGateway | Hybrid | Same as web servers — compatibility + PQ protection |
| IoT | Classic | Resource-constrained devices may not support PQ KEM |
| LegacyIntegration | Classic | Legacy systems don't support PQ at all |
| FinancialServices | Hybrid | Regulated but PQ-only would break existing integrations |
| Healthcare | Hybrid | HIPAA compliance + forward secrecy with PQ |
| Government | Pq | Strictest requirements — fully post-quantum |
| DatabaseConnection | Hybrid | Internal but high-value target |
| RealTimeStreaming | Classic | Latency-sensitive; PQ KEM adds ~1KB overhead per handshake |

### 11b: SecurityLevel to TLS Mode (4 proof lines)

Similar to Section 2 but for TLS. Standard/High/Maximum all map to Hybrid; Quantum maps to PQ-only.

### 11c: TLS 1.3 Config Conversion (3 proof lines)

#### What This Tests

`TlsConfig` (high-level) converts to `Tls13Config` (wire-level). The test verifies that the `use_pq_kx` flag (post-quantum key exchange) is set correctly for each mode.

```json
{
  "section": 11,
  "test": "tls13_config_Hybrid",
  "mode": "Hybrid",
  "use_pq_kx": true,
  "protocol": "TLS 1.3",
  "status": "PASS"
}
```

| Field | Meaning |
|-------|---------|
| `mode` | Classic / Hybrid / Pq |
| `use_pq_kx` | Whether the TLS 1.3 handshake uses PQ key exchange (X25519MLKEM768) |
| `protocol` | Always "TLS 1.3" — PQ key exchange only works with TLS 1.3 |

Classic = `use_pq_kx: false` (only X25519). Hybrid and PQ = `use_pq_kx: true` (includes ML-KEM-768).

### 11d: PQ Key Exchange Info (3 proof lines)

#### What This Tests

The `get_kex_info()` API returns metadata about the key exchange for each mode. This test verifies the key sizes, ciphertext sizes, shared secret sizes, and PQ-security flag.

```json
{
  "section": 11,
  "test": "kex_info_Hybrid_RustlsPq",
  "method": "X25519MLKEM768",
  "is_pq_secure": true,
  "pk_size": 1216,
  "ct_size": 1120,
  "ss_size": 64,
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `method` | The key exchange algorithm name | X25519MLKEM768 = hybrid; X25519 (ECDHE) = classical |
| `is_pq_secure` | Whether this KE resists quantum attacks | The whole point of the migration — Hybrid and PQ modes are PQ-secure |
| `pk_size` | Public key size: 1216 = X25519(32) + ML-KEM-768(1184) | Shows both components are present in hybrid mode |
| `ct_size` | Ciphertext size: 1120 = X25519(32) + ML-KEM-768(1088) | The data sent from client to server during handshake |
| `ss_size` | Shared secret: 64 = X25519(32) + ML-KEM(32), then KDF'd | Both shared secrets are combined for key derivation |

For Classic mode: pk=32, ct=32, ss=32 — just X25519.

### 11e: TLS Config Validation (1 proof line)

Verifies that the config builder produces valid configurations — default config is valid, and a fully-specified builder chain is also valid.

### 11f: Live TLS Handshakes (2 proof lines)

#### What This Tests

The two most important proofs in this section: **actual TLS handshakes to a real server** (cloudflare.com:443).

1. **Hybrid handshake**: Uses X25519MLKEM768 key exchange — post-quantum secure
2. **Classic handshake**: Uses X25519 only — for comparison

These are not mocks. The test opens a TCP connection, performs a full TLS 1.3 handshake with the configured key exchange algorithm, and reports whether it succeeded.

#### Real-World Scenario

This IS the real world. Cloudflare supports both X25519 and X25519MLKEM768 on their production servers. The hybrid handshake proves that LatticeArc's TLS implementation can negotiate a post-quantum-secure session with a real Internet server.

```json
{
  "section": 11,
  "test": "tls_live_hybrid_handshake",
  "server": "cloudflare.com:443",
  "mode": "Hybrid",
  "kex": "X25519MLKEM768",
  "protocol": "TLS 1.3",
  "handshake": "SUCCESS",
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `server` | The real server connected to | cloudflare.com — a production Internet server |
| `mode` | Hybrid or Classic | Which TLS configuration was used |
| `kex` | The key exchange algorithm negotiated | X25519MLKEM768 = post-quantum hybrid; X25519 = classical only |
| `protocol` | TLS 1.3 | PQ key exchange requires TLS 1.3 |
| `handshake` | SUCCESS or NETWORK_UNAVAILABLE | SUCCESS means the full TLS handshake completed — certificate validation, key exchange, and session establishment |

---

## Section 12: Data-at-Rest Byte-Exact Preservation (9 proof lines)

### What This Tests

The complete data-at-rest pipeline:
1. Hash the plaintext with SHA3-256 (the "before" fingerprint)
2. Encrypt the plaintext using hybrid encryption
3. Serialize the `EncryptedOutput` to JSON (simulates writing to disk)
4. Deserialize from JSON (simulates reading from disk)
5. Verify all metadata fields survived serialization (scheme, nonce, tag, hybrid data)
6. Decrypt from the deserialized output
7. Hash the decrypted data with SHA3-256 (the "after" fingerprint)
8. Assert the hashes are identical AND the raw bytes are identical

This is tested with 9 different payload types:
- **Structured JSON** — a config file with nested objects, special characters
- **Binary data** — all 256 possible byte values including null bytes and control characters
- **Unicode text** — English, Chinese, Arabic, Russian, emoji
- **Empty payload** — zero bytes
- **ML-KEM-512 pipeline** — full roundtrip at lowest security level
- **ML-KEM-768 pipeline** — full roundtrip at medium level
- **ML-KEM-1024 pipeline** — full roundtrip at highest level
- **64KB document** — a large file with numbered lines
- **AAD context-binding** — encryption with additional authenticated data

### Real-World Scenario

A compliance system archives encrypted healthcare records. Years later, an auditor retrieves a record, deserializes it, and decrypts it. The record MUST be byte-identical to what was originally encrypted — not "similar," not "equivalent," but THE EXACT SAME BYTES. A single bit difference could mean a corrupted medical record, a failed audit, or a legal liability.

The SHA3-256 hash comparison provides cryptographic assurance: the probability of different data producing the same 256-bit hash is 2^-128 (essentially zero). If `sha3_256_before == sha3_256_after`, the data is identical with overwhelming probability.

### Proof Fields Explained

```json
{
  "section": 12,
  "test": "at_rest_ml_kem_768_pipeline",
  "description": "Full pipeline at ML-KEM-768",
  "plaintext_len": 100,
  "scheme": "hybrid-ml-kem-768-aes-256-gcm",
  "json_serialized_bytes": 1847,
  "sha3_256_before": "95c494785ab55d57e4041186e163e6fb751ab3bac7078c7ecd2212083b017c48",
  "sha3_256_after": "95c494785ab55d57e4041186e163e6fb751ab3bac7078c7ecd2212083b017c48",
  "hash_match": true,
  "byte_exact_match": true,
  "scheme_preserved": true,
  "nonce_preserved": true,
  "tag_preserved": true,
  "hybrid_data_preserved": true,
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `description` | Human-readable test description | Explains what kind of data is being tested |
| `plaintext_len` | Input data size in bytes | Ranges from 0 (empty) to 65,475 (64KB document) |
| `scheme` | The hybrid encryption scheme used | Varies by ML-KEM level — proves the scheme tag survives the full pipeline |
| `json_serialized_bytes` | Size of the JSON blob written to "disk" | Shows the storage overhead: a 100-byte plaintext becomes ~1,847 bytes of JSON (includes base64-encoded ciphertext, KEM ciphertext, nonce, tag, scheme tag, etc.) |
| `sha3_256_before` | SHA3-256 hash of the original plaintext | The cryptographic fingerprint taken BEFORE any encryption |
| `sha3_256_after` | SHA3-256 hash of the decrypted output | The cryptographic fingerprint taken AFTER the full encrypt-serialize-deserialize-decrypt pipeline |
| `hash_match` | `sha3_256_before == sha3_256_after` | The primary proof — cryptographic assurance of data integrity across the full pipeline |
| `byte_exact_match` | Raw byte comparison `decrypted == plaintext` | Belt-and-suspenders: in addition to the hash, a direct byte comparison |
| `scheme_preserved` | The scheme tag survived JSON serialization | Without this, the decryptor wouldn't know which algorithm to use |
| `nonce_preserved` | The 12-byte nonce survived serialization | Wrong nonce = wrong decryption |
| `tag_preserved` | The 16-byte auth tag survived serialization | Wrong tag = authentication failure |
| `hybrid_data_preserved` | ML-KEM ciphertext + ECDH PK survived serialization | These are the KEM components — both must be exact |

### AAD Context-Binding Proof

```json
{
  "section": 12,
  "test": "at_rest_aad_context_binding",
  "description": "AAD-bound encryption at rest",
  "plaintext_len": 60,
  "aad": "context:healthcare:patient:12345",
  "sha3_256_before": "d04f3db418cd1083112ad57254ffb3baf0636f9e2c9c8f2b01bc49350becddfe",
  "sha3_256_after": "d04f3db418cd1083112ad57254ffb3baf0636f9e2c9c8f2b01bc49350becddfe",
  "hash_match": true,
  "byte_exact_match": true,
  "wrong_aad_rejected": true,
  "status": "PASS"
}
```

| Field | Meaning | Why It Matters |
|-------|---------|----------------|
| `aad` | The context string bound to the ciphertext | `"context:healthcare:patient:12345"` — identifies which patient this record belongs to |
| `wrong_aad_rejected` | Decryption with a different AAD was rejected | Proves the ciphertext cannot be reused in a different context |

This models a healthcare system where each encrypted record is bound to a specific patient ID. Copying the ciphertext to another patient's file and trying to decrypt fails because the AAD doesn't match.

### Notable SHA3-256 Values

- **Empty input**: `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` — this is the well-known SHA3-256 hash of the empty string, verifiable against any reference implementation
- All other hashes are deterministic: the same input always produces the same hash, so these values are reproducible

---

## Summary: What the 89 Proof Lines Collectively Prove

| Claim | Evidence |
|-------|----------|
| **Policy engine selects correct algorithm for every use case** | 22 UseCase proofs + 4 SecurityLevel proofs (Section 1, 2) |
| **ML-KEM parameters match NIST FIPS 203** | 3 parameter verification proofs with live keygen (Section 3) |
| **Encryption works for any payload size** | 5 variable-size roundtrips from 0B to 1MB (Section 4) |
| **All 6 signature algorithms produce valid signatures** | 6 sign-then-verify proofs across FIPS 204/205/206 (Section 5) |
| **Serialization preserves all cryptographic metadata** | 3 serialize-then-decrypt proofs (Section 6) |
| **Wrong keys are always rejected** | 4 negative proofs (Section 7) |
| **Any data corruption is detected** | 5 single-byte-flip proofs across all fields (Section 8) |
| **AAD context binding is enforced** | 2 AAD mismatch proofs (Section 9) |
| **Key/scheme level mismatches are caught immediately** | 3 cross-level proofs (Section 10) |
| **TLS policy engine selects correct mode for all use cases** | 10 TLS UseCase proofs + 4 SecurityLevel proofs (Section 11) |
| **PQ key exchange works with real Internet servers** | 2 live TLS handshake proofs (Section 11) |
| **Data-at-rest survives full pipeline byte-for-byte** | 9 SHA3-256-verified roundtrip proofs (Section 12) |

Every proof line represents a REAL cryptographic operation — not a mock, not a simulation. Keys were generated, data was encrypted/signed with those keys, and the result was verified. The structured JSON format makes these proofs machine-parseable for automated compliance reporting.
