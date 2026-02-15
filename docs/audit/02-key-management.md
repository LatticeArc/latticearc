# Dimension 2: Key Lifecycle

**Last audited:** 2026-02-15
**Auditor:** Agent a78f596 + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

None.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 2.1 Key gen CSPRNG | `aes_gcm.rs` | 166-170, 304-309 | `OsRng.fill_bytes(&mut key)` |
| 2.1 ML-KEM keygen | `ml_kem.rs` | 831 | aws-lc-rs FIPS-approved DRBG |
| 2.2 MlKemSecretKey Zeroize | `ml_kem.rs` | 523-529 | `impl Zeroize` + `impl ZeroizeOnDrop` |
| 2.2 MlDsaSecretKey Zeroize | `ml_dsa.rs` | 229 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| 2.2 AesGcm128 Zeroize | `aes_gcm.rs` | 52 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| 2.2 AesGcm256 Zeroize | `aes_gcm.rs` | 191 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| 2.2 X25519SecretKey Zeroize | `ecdh.rs` | 216 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| 2.2 SecureBytes Zeroize | `security.rs` | 20 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| 2.2 SecretKey Zeroize | `keys/mod.rs` | 204 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| 2.3 No Clone on MlKemSecretKey | `ml_kem.rs` | 448-530 | No Clone derive |
| 2.3 No Clone on MlDsaSecretKey | `ml_dsa.rs` | 229-308 | No Clone derive |
| 2.3 No Clone on X25519SecretKey | `ecdh.rs` | 216 | No Clone derive |
| 2.3 No Clone on SecureBytes | `security.rs` | 20 | No Clone derive |
| 2.3 No Clone on HkdfResult | `hkdf.rs` | derive | Clone removed (2026-02-15 fix) |
| 2.3 No Clone on Pbkdf2Result | `pbkdf2.rs` | derive | Clone removed (2026-02-15 fix) |
| 2.3 No Clone on HashOpening | `commitment.rs` | derive | Clone removed (2026-02-15 fix) |
| 2.4 No Debug leaks MlKemSecretKey | `ml_kem.rs` | 456-463 | Custom Debug: `data: "[REDACTED]"` |
| 2.4 No Debug leaks MlDsaSecretKey | `ml_dsa.rs` | 238-245 | Custom Debug: `data: "[REDACTED]"` |
| 2.5 into_bytes() returns Zeroizing | `ml_kem.rs` | 504-506 | `Zeroizing<Vec<u8>>` (2026-02-15 fix) |
| 2.7 Exact key size (AES) | `aes_gcm.rs` | 62-64, 200-203 | Uses `!=` not `<` |
| 2.7 Exact key size (ML-KEM) | `ml_kem.rs` | 332-339 | Exact match with error |
