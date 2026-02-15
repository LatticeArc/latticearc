# Dimension 7: Documentation Accuracy

**Last audited:** 2026-02-15
**Auditor:** Agent a0044cc + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

### F7-01: AES-GCM unverified wrapper docs said truncation, code rejects [VERIFIED]

**Severity:** MEDIUM
**File:** `arc-core/src/convenience/aes_gcm.rs`
**Issue:** Unverified wrapper docs claimed key truncation; code actually rejects != 32 bytes.
**Resolution:** Updated docs to: "The `key` must be exactly 32 bytes. Any other key length returns an error."

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 7.1 Verified AES-GCM docs match code | `aes_gcm.rs` | 201-202 | "exactly 32 bytes" matches `key.len() != 32` check |
| 7.3 HKDF salt warning | `hkdf.rs` | 60-77 | Salt Usage section: random salt recommended |
| 7.3 AES-GCM nonce warning | `aes_gcm.rs` | 7-10 | Nonce Management section: 2^32 collision risk, key rotation |
| 7.3 self_test.rs canonical status | `self_test.rs` | 1-9 | Identifies as canonical FIPS module vs arc-validation |
| 7.6 ML-KEM FIPS limitation stated | `pq_kem.rs` | 5-42 | Extensive doc: decryption limitation + 3 alternatives |
| 7.7 Integrity test FIPS notes | `self_test.rs` | 1032-1037 | Documents HSM/TPM/secure-boot requirements |
| PBKDF2 iteration docs | `pbkdf2.rs` | 37, 179-190 | Min 1000, max 10M documented and enforced |
